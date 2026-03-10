// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Support for C2PA Live Video validation (section 19 of the C2PA Technical Specification).
//!
//! Implements two validation methods:
//!
//! - **Section 19.3** (per-segment C2PA Manifest Box): each segment carries its own C2PA
//!   Manifest with a [`LiveVideoSegment`] assertion. Use [`LiveVideoValidator::validate_media_segment`].
//!
//! - **Section 19.4** (Verifiable Segment Info): the init segment manifest contains a
//!   [`crate::assertions::SessionKeys`] assertion; each media segment carries a COSE_Sign1 in
//!   an `emsg` box. Use [`LiveVideoValidator::validate_session_keys`] and
//!   [`LiveVideoValidator::validate_verifiable_segment_info`].
//!
//! See [C2PA Technical Specification — Live Video](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_live_video).

pub(crate) mod cose_key;
pub mod verifiable_segment_info;

use std::io::{Cursor, Read, Seek, SeekFrom};

use crate::{
    assertions::{ContinuityMethod, LiveVideoSegment, SessionKey, SessionKeys},
    crypto::raw_signature::validator_for_signing_alg,
    error::{Error, Result},
    log_item,
    status_tracker::StatusTracker,
    validation_results::validation_codes::{
        LIVEVIDEO_ASSERTION_INVALID, LIVEVIDEO_CONTINUITY_METHOD_INVALID,
        LIVEVIDEO_INIT_INVALID, LIVEVIDEO_MANIFEST_INVALID, LIVEVIDEO_SEGMENT_INVALID,
        LIVEVIDEO_SESSIONKEY_INVALID,
    },
};

use self::{
    cose_key::{cose_key_to_der, kid_from_cose_key, signing_alg_from_cose_key},
    verifiable_segment_info::{extract_vsi_payload_from_segment, parse_vsi},
};

const MDAT_BOX_TYPE: u32 = 0x6d646174;
const UUID_BOX_TYPE: u32 = 0x75756964;
const EMSG_BOX_TYPE: u32 = 0x656d7367;


/// C2PA UUID identifying a `uuid` box that contains a C2PA Manifest Store.
const C2PA_UUID: [u8; 16] = [
    0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c,
    0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81,
];

fn fail_validation(
    description: impl Into<String>,
    status_code: &'static str,
    tracker: &mut StatusTracker,
) -> Result<()> {
    let description: String = description.into();
    log_item!("live_video", description, "LiveVideoValidator")
        .validation_status(status_code)
        .failure(tracker, Error::BadParam(status_code.into()))?;
    Ok(())
}

struct SegmentState {
    sequence_number: u64,
    stream_id: String,
    manifest_id: String,
}

/// Validates a sequence of live video segments against C2PA section 19 rules.
///
/// Supports section [19.3] (per-segment C2PA Manifest Box) and section [19.4] (Verifiable
/// Segment Info). Create one instance per live stream; for 19.4 call
/// [`validate_session_keys`] after [`validate_init_segment`].
///
/// [19.3]: https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#using_c2pa_manifest_box
/// [19.4]: https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#verifiable_segment_info
/// [`validate_session_keys`]: LiveVideoValidator::validate_session_keys
/// [`validate_init_segment`]: LiveVideoValidator::validate_init_segment
pub struct LiveVideoValidator {
    previous_segment: Option<SegmentState>,
    session_keys: Vec<SessionKey>,
}

impl LiveVideoValidator {
    pub fn new() -> Self {
        Self {
            previous_segment: None,
            session_keys: Vec::new(),
        }
    }

    /// Validates an initialization segment ([§19.7.1]).
    ///
    /// [§19.7.1]: https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_live_video_validation_process
    pub fn validate_init_segment(
        &self,
        segment_data: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if segment_contains_box_type(segment_data, MDAT_BOX_TYPE) {
            fail_validation(
                "initialization segment must not contain an mdat box",
                LIVEVIDEO_INIT_INVALID,
                tracker,
            )?;
        }
        Ok(())
    }

    /// Records a manifest-level validation failure for a segment ([§19.3]).
    ///
    /// Use this when the segment's C2PA manifest cannot be read or has no active manifest.
    ///
    /// [§19.3]: https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#using_c2pa_manifest_box
    pub fn fail_segment_manifest(
        &self,
        description: impl Into<String>,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        fail_validation(description, LIVEVIDEO_MANIFEST_INVALID, tracker)
    }

    /// Validates a media segment using the per-segment C2PA Manifest Box method ([§19.3]).
    ///
    /// [§19.3]: https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#using_c2pa_manifest_box
    pub fn validate_media_segment(
        &mut self,
        segment_data: &[u8],
        manifest_id: &str,
        assertion: &LiveVideoSegment,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        self.validate_segment_has_c2pa_or_emsg(segment_data, tracker)?;
        self.validate_continuity_rules(assertion, manifest_id, tracker)?;

        if let Some(previous) = &self.previous_segment {
            self.validate_sequence_number(assertion, previous, tracker)?;
            self.validate_stream_id(assertion, previous, tracker)?;
        }

        self.previous_segment = Some(SegmentState {
            sequence_number: assertion.sequence_number,
            stream_id: assertion.stream_id.clone(),
            manifest_id: manifest_id.to_string(),
        });

        Ok(())
    }

    fn validate_segment_has_c2pa_or_emsg(
        &self,
        segment_data: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        let has_c2pa_manifest_box = segment_contains_c2pa_uuid_box(segment_data);
        let has_emsg_box = segment_contains_box_type(segment_data, EMSG_BOX_TYPE);

        if !has_c2pa_manifest_box && !has_emsg_box {
            fail_validation(
                "segment must contain a C2PA Manifest Box (uuid) or an emsg box",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            )?;
        }
        Ok(())
    }

    fn validate_sequence_number(
        &self,
        assertion: &LiveVideoSegment,
        previous: &SegmentState,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if assertion.sequence_number <= previous.sequence_number {
            fail_validation(
                "sequenceNumber must be strictly greater than the previous segment's",
                LIVEVIDEO_ASSERTION_INVALID,
                tracker,
            )?;
        }
        Ok(())
    }

    fn validate_stream_id(
        &self,
        assertion: &LiveVideoSegment,
        previous: &SegmentState,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if assertion.stream_id != previous.stream_id {
            fail_validation(
                "streamId must match the previous segment's streamId",
                LIVEVIDEO_ASSERTION_INVALID,
                tracker,
            )?;
        }
        Ok(())
    }

    fn validate_continuity_rules(
        &self,
        assertion: &LiveVideoSegment,
        manifest_id: &str,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        match &assertion.continuity_method {
            ContinuityMethod::ManifestId => {
                self.validate_manifest_id_continuity(assertion, manifest_id, tracker)
            }
            ContinuityMethod::Unknown(method) => {
                fail_validation(
                    format!("unsupported continuity method: {method}"),
                    LIVEVIDEO_CONTINUITY_METHOD_INVALID,
                    tracker,
                )
            }
        }
    }

    /// Validates a `c2pa.session-keys` assertion and stores the keys for VSI verification ([§19.4]).
    ///
    /// [§19.4]: https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#verifiable_segment_info
    pub fn validate_session_keys(
        &mut self,
        assertion: &SessionKeys,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if assertion.keys.is_empty() {
            return fail_validation(
                "session-keys assertion must contain at least one key",
                LIVEVIDEO_SESSIONKEY_INVALID,
                tracker,
            );
        }

        for key in &assertion.keys {
            if kid_from_cose_key(&key.key).is_none() {
                return fail_validation(
                    "session key COSE_Key must include a kid (key identifier)",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }

            if key.validity_period == 0 {
                return fail_validation(
                    "session key validityPeriod must be greater than zero",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }

            // TODO: verify signerBinding — the COSE_Sign1 should be verified using the
            // session key's private counterpart against the signer's end-entity certificate
            // (§19.7.3). Requires access to the certificate chain from the manifest signature,
            // which is not yet plumbed through to this validation path.
        }

        self.session_keys = assertion.keys.clone();
        Ok(())
    }

    /// Validates a media segment using the Verifiable Segment Info method ([§19.4]).
    ///
    /// [§19.4]: https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#verifiable_segment_info
    pub fn validate_verifiable_segment_info(
        &mut self,
        segment_data: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        self.require_session_keys(tracker)?;
        let parsed = self.extract_and_parse_vsi(segment_data, tracker)?;
        let session_key = self.resolve_session_key(&parsed.sign1, tracker)?;
        let seq_num = parsed.segment_info_map.sequence_number;

        self.validate_vsi_sequence_bounds(seq_num, &session_key, tracker)?;
        self.validate_vsi_key_validity(&session_key, tracker)?;
        self.validate_vsi_signature(&parsed.sign1, &session_key, tracker)?;
        self.validate_vsi_sequence_continuity(seq_num, tracker)?;
        // TODO: validate bmffHash — verify the segment's content hash against
        // parsed.segment_info_map.bmff_hash (§19.7.3). Requires running the BMFF
        // hash computation over segment_data with the exclusions defined in §19.4.1,
        // which depends on the bmff-hash infrastructure not yet wired into this path.

        self.previous_segment = Some(SegmentState {
            sequence_number: seq_num,
            stream_id: String::new(),
            manifest_id: parsed.segment_info_map.manifest_id.clone(),
        });

        Ok(())
    }

    fn require_session_keys(&self, tracker: &mut StatusTracker) -> Result<()> {
        if self.session_keys.is_empty() {
            return fail_validation(
                "no session keys available; validate_session_keys must be called first",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }
        Ok(())
    }

    fn extract_and_parse_vsi(
        &self,
        segment_data: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<verifiable_segment_info::ParsedVsi> {
        let vsi_bytes = match extract_vsi_payload_from_segment(segment_data) {
            Some(bytes) => bytes,
            None => {
                fail_validation(
                    "segment must contain a VSI emsg box (urn:c2pa:verifiable-segment-info)",
                    LIVEVIDEO_SEGMENT_INVALID,
                    tracker,
                )?;
                return Err(Error::BadParam("livevideo.segment.invalid".into()));
            }
        };

        parse_vsi(&vsi_bytes).map_err(|_| {
            let _ = fail_validation(
                "failed to parse SegmentInfoMap from VSI COSE_Sign1 payload",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
            Error::BadParam("livevideo.segment.invalid".into())
        })
    }

    fn resolve_session_key(
        &self,
        sign1: &coset::CoseSign1,
        tracker: &mut StatusTracker,
    ) -> Result<SessionKey> {
        let kid = &sign1.unprotected.key_id;
        if kid.is_empty() {
            fail_validation(
                "COSE_Sign1 unprotected header must contain a kid identifying the session key",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            )?;
            return Err(Error::BadParam("livevideo.segment.invalid".into()));
        }

        match self.find_session_key_by_kid(kid) {
            Some(sk) => Ok(sk),
            None => {
                fail_validation(
                    "no session key matches the kid in the COSE_Sign1 unprotected header",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                )?;
                Err(Error::BadParam("livevideo.sessionkey.invalid".into()))
            }
        }
    }

    fn validate_vsi_sequence_bounds(
        &self,
        seq_num: u64,
        session_key: &SessionKey,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if seq_num < session_key.min_sequence_number {
            return fail_validation(
                "sequenceNumber is below the session key's minSequenceNumber",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }
        Ok(())
    }

    fn validate_vsi_key_validity(
        &self,
        session_key: &SessionKey,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if let Err(msg) = self.check_key_validity_period(session_key) {
            return fail_validation(msg, LIVEVIDEO_SESSIONKEY_INVALID, tracker);
        }
        Ok(())
    }

    fn validate_vsi_signature(
        &self,
        sign1: &coset::CoseSign1,
        session_key: &SessionKey,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if let Err(msg) = self.verify_cose_sign1(sign1, session_key) {
            return fail_validation(msg, LIVEVIDEO_SEGMENT_INVALID, tracker);
        }
        Ok(())
    }

    fn validate_vsi_sequence_continuity(
        &self,
        seq_num: u64,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if let Some(previous) = &self.previous_segment {
            if seq_num <= previous.sequence_number {
                return fail_validation(
                    "VSI sequenceNumber must be strictly greater than the previous segment's",
                    LIVEVIDEO_ASSERTION_INVALID,
                    tracker,
                );
            }
        }
        Ok(())
    }

    fn find_session_key_by_kid(&self, kid: &[u8]) -> Option<SessionKey> {
        self.session_keys.iter().find(|sk| {
            kid_from_cose_key(&sk.key)
                .map(|k| k == kid)
                .unwrap_or(false)
        }).cloned()
    }

    fn check_key_validity_period(&self, key: &SessionKey) -> std::result::Result<(), String> {
        use chrono::{DateTime, Duration, Utc};

        let created_at: DateTime<Utc> = key
            .created_at
            .0
            .parse()
            .map_err(|_| "session key createdAt is not a valid RFC 3339 datetime".to_string())?;

        let validity_seconds = i64::try_from(key.validity_period)
            .map_err(|_| "validityPeriod overflow".to_string())?;

        let expires_at = created_at + Duration::seconds(validity_seconds);
        let now = Utc::now();

        if now > expires_at {
            return Err(format!(
                "session key expired: createdAt={}, validityPeriod={}s, now={}",
                key.created_at.0, key.validity_period, now
            ));
        }

        Ok(())
    }

    fn verify_cose_sign1(
        &self,
        sign1: &coset::CoseSign1,
        session_key: &SessionKey,
    ) -> std::result::Result<(), String> {
        let alg = signing_alg_from_cose_key(&session_key.key)
            .ok_or_else(|| "unsupported key type/curve in session key".to_string())?;

        let public_key_der = cose_key_to_der(&session_key.key)
            .ok_or_else(|| "failed to convert session key to DER".to_string())?;

        let validator = validator_for_signing_alg(alg)
            .ok_or_else(|| format!("no validator available for {alg:?}"))?;

        let tbs = sign1.tbs_data(b"");

        validator
            .validate(&sign1.signature, &tbs, &public_key_der)
            .map_err(|e| format!("COSE_Sign1 signature verification failed: {e}"))
    }

    fn validate_manifest_id_continuity(
        &self,
        assertion: &LiveVideoSegment,
        _current_manifest_id: &str,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        let Some(previous) = &self.previous_segment else {
            return Ok(());
        };

        let previous_manifest_id = match &assertion.previous_manifest_id {
            Some(id) => id,
            None => {
                return fail_validation(
                    "previousManifestId is required when continuityMethod is c2pa.manifestId",
                    LIVEVIDEO_CONTINUITY_METHOD_INVALID,
                    tracker,
                );
            }
        };

        if previous_manifest_id != &previous.manifest_id {
            fail_validation(
                "previousManifestId does not match the previous segment's manifest identifier",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            )?;
        }
        Ok(())
    }
}

impl Default for LiveVideoValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns `true` if the BMFF data contains a top-level box with the given FourCC type.
fn segment_contains_box_type(data: &[u8], target_type: u32) -> bool {
    let mut cursor = Cursor::new(data);
    loop {
        let box_start = cursor.stream_position().unwrap_or(0);
        match read_box_header(&mut cursor) {
            Ok((box_type, box_size)) => {
                if box_type == target_type {
                    return true;
                }
                // box_size is the total size from the start of the box header.
                let next = box_start + box_size;
                if cursor.seek(SeekFrom::Start(next)).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    false
}

/// Returns `true` if the BMFF data contains a `uuid` box with the C2PA Manifest Store UUID.
fn segment_contains_c2pa_uuid_box(data: &[u8]) -> bool {
    let mut cursor = Cursor::new(data);
    loop {
        let box_start = cursor.stream_position().unwrap_or(0);
        match read_box_header(&mut cursor) {
            Ok((box_type, box_size)) => {
                if box_type == UUID_BOX_TYPE {
                    let mut uuid_bytes = [0u8; 16];
                    if cursor.read_exact(&mut uuid_bytes).is_ok() && uuid_bytes == C2PA_UUID {
                        return true;
                    }
                }
                // box_size is the total size from the start of the box header.
                let next = box_start + box_size;
                if cursor.seek(SeekFrom::Start(next)).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    false
}

/// Reads a single ISO BMFF box header and returns `(fourcc, total_box_size_in_bytes)`.
fn read_box_header<R: Read + Seek>(reader: &mut R) -> Result<(u32, u64)> {
    let mut header = [0u8; 8];
    reader.read_exact(&mut header).map_err(|_| Error::NotFound)?;

    let size = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let box_type = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

    let total_size = if size == 1 {
        // Extended (64-bit) size field follows the 8-byte header.
        let mut large_size_bytes = [0u8; 8];
        reader
            .read_exact(&mut large_size_bytes)
            .map_err(|_| Error::NotFound)?;
        u64::from_be_bytes(large_size_bytes)
    } else if size == 0 {
        // Size == 0 means "extends to end of stream"; treat as very large.
        u64::MAX
    } else {
        size as u64
    };

    Ok((box_type, total_size))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::collections::HashMap;

    use super::*;
    use crate::{
        assertions::{ContinuityMethod, LiveVideoSegment, SessionKey, SessionKeys},
        cbor_types::DateT,
        status_tracker::StatusTracker,
    };

    fn make_segment(sequence_number: u64, stream_id: &str) -> LiveVideoSegment {
        LiveVideoSegment {
            sequence_number,
            stream_id: stream_id.to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: Some("urn:c2pa:prev-manifest".to_string()),
            additional_fields: HashMap::new(),
        }
    }

    fn make_uuid_box(include_c2pa_uuid: bool) -> Vec<u8> {
        let mut data = Vec::new();
        // size: 8 header + 16 uuid = 24
        let size: u32 = 24;
        data.extend_from_slice(&size.to_be_bytes());
        data.extend_from_slice(b"uuid");
        if include_c2pa_uuid {
            data.extend_from_slice(&C2PA_UUID);
        } else {
            data.extend_from_slice(&[0u8; 16]);
        }
        data
    }

    fn make_mdat_box() -> Vec<u8> {
        let mut data = Vec::new();
        let size: u32 = 8;
        data.extend_from_slice(&size.to_be_bytes());
        data.extend_from_slice(b"mdat");
        data
    }

    fn make_emsg_box() -> Vec<u8> {
        let mut data = Vec::new();
        let size: u32 = 8;
        data.extend_from_slice(&size.to_be_bytes());
        data.extend_from_slice(b"emsg");
        data
    }

    fn aggregate_tracker() -> StatusTracker {
        StatusTracker::default()
    }

    #[test]
    fn init_segment_without_mdat_is_valid() {
        let validator = LiveVideoValidator::new();
        let segment = make_uuid_box(true);
        let mut tracker = aggregate_tracker();

        validator
            .validate_init_segment(&segment, &mut tracker)
            .unwrap();

        let failures: Vec<_> = tracker
            .logged_items()
            .iter()
            .filter(|i| {
                i.validation_status
                    .as_deref()
                    .map(|s| s.starts_with("livevideo"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(failures.is_empty());
    }

    #[test]
    fn init_segment_with_mdat_fails() {
        let validator = LiveVideoValidator::new();
        let mut segment = make_uuid_box(true);
        segment.extend(make_mdat_box());
        let mut tracker = aggregate_tracker();

        let _ = validator.validate_init_segment(&segment, &mut tracker);

        let has_init_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_INIT_INVALID)
        });
        assert!(has_init_invalid);
    }

    #[test]
    fn fail_segment_manifest_records_manifest_invalid() {
        let validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let _ = validator.fail_segment_manifest("no active manifest in segment", &mut tracker);

        let has_manifest_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_MANIFEST_INVALID)
        });
        assert!(has_manifest_invalid);
    }

    #[test]
    fn media_segment_without_c2pa_or_emsg_fails() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_mdat_box();
        let assertion = make_segment(1, "stream-1");
        let mut tracker = aggregate_tracker();

        let _ = validator.validate_media_segment(
            &segment_data,
            "urn:c2pa:manifest-1",
            &assertion,
            &mut tracker,
        );

        let has_segment_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID)
        });
        assert!(has_segment_invalid);
    }

    #[test]
    fn valid_sequence_advances_state() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_uuid_box(true);
        let mut tracker = aggregate_tracker();

        let first = LiveVideoSegment {
            sequence_number: 1,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        validator
            .validate_media_segment(&segment_data, "urn:c2pa:manifest-1", &first, &mut tracker)
            .unwrap();

        let second = LiveVideoSegment {
            sequence_number: 2,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: Some("urn:c2pa:manifest-1".to_string()),
            additional_fields: HashMap::new(),
        };
        validator
            .validate_media_segment(&segment_data, "urn:c2pa:manifest-2", &second, &mut tracker)
            .unwrap();

        let live_failures: Vec<_> = tracker
            .logged_items()
            .iter()
            .filter(|i| {
                i.validation_status
                    .as_deref()
                    .map(|s| s.starts_with("livevideo"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(live_failures.is_empty());
    }

    #[test]
    fn regressed_sequence_number_fails() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_uuid_box(true);
        let mut tracker = aggregate_tracker();

        let first = LiveVideoSegment {
            sequence_number: 5,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-1", &first, &mut tracker);

        let second = LiveVideoSegment {
            sequence_number: 4, // regressed!
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: Some("manifest-1".to_string()),
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-2", &second, &mut tracker);

        let has_assertion_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_ASSERTION_INVALID)
        });
        assert!(has_assertion_invalid);
    }

    #[test]
    fn mismatched_stream_id_fails() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_uuid_box(true);
        let mut tracker = aggregate_tracker();

        let first = LiveVideoSegment {
            sequence_number: 1,
            stream_id: "stream-A".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-1", &first, &mut tracker);

        let second = LiveVideoSegment {
            sequence_number: 2,
            stream_id: "stream-B".to_string(), // different!
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: Some("manifest-1".to_string()),
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-2", &second, &mut tracker);

        let has_assertion_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_ASSERTION_INVALID)
        });
        assert!(has_assertion_invalid);
    }

    #[test]
    fn missing_previous_manifest_id_fails_with_continuity_method_invalid() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_uuid_box(true);
        let mut tracker = aggregate_tracker();

        // Advance state to segment 1
        let first = LiveVideoSegment {
            sequence_number: 1,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-1", &first, &mut tracker);

        // Segment 2 missing previousManifestId
        let second = LiveVideoSegment {
            sequence_number: 2,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None, // missing!
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-2", &second, &mut tracker);

        let has_continuity_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_CONTINUITY_METHOD_INVALID)
        });
        assert!(has_continuity_invalid);
    }

    #[test]
    fn wrong_previous_manifest_id_fails_with_segment_invalid() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_uuid_box(true);
        let mut tracker = aggregate_tracker();

        let first = LiveVideoSegment {
            sequence_number: 1,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-1", &first, &mut tracker);

        let second = LiveVideoSegment {
            sequence_number: 2,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: Some("manifest-WRONG".to_string()), // incorrect!
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-2", &second, &mut tracker);

        let has_segment_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID)
        });
        assert!(has_segment_invalid);
    }

    #[test]
    fn unknown_continuity_method_fails() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_uuid_box(true);
        let mut tracker = aggregate_tracker();

        let assertion = LiveVideoSegment {
            sequence_number: 1,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::Unknown("vendor.custom".to_string()),
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        let _ = validator.validate_media_segment(
            &segment_data,
            "manifest-1",
            &assertion,
            &mut tracker,
        );

        let has_continuity_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_CONTINUITY_METHOD_INVALID)
        });
        assert!(has_continuity_invalid);
    }

    #[test]
    fn emsg_box_satisfies_presence_check() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_emsg_box();
        let mut tracker = aggregate_tracker();

        let assertion = LiveVideoSegment {
            sequence_number: 1,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        // Should NOT produce livevideo.segment.invalid for missing C2PA box
        let _ = validator.validate_media_segment(
            &segment_data,
            "manifest-1",
            &assertion,
            &mut tracker,
        );

        let has_segment_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID)
        });
        assert!(!has_segment_invalid);
    }

    // ── 19.4 helpers ──────────────────────────────────────────────────────────

    fn cbor_int(val: i64) -> c2pa_cbor::Value {
        c2pa_cbor::Value::Integer(val)
    }

    fn minimal_session_keys() -> SessionKeys {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(1), cbor_int(2));   // kty: EC2
        map.insert(cbor_int(2), c2pa_cbor::Value::Bytes(b"k".to_vec())); // kid
        map.insert(cbor_int(-1), cbor_int(1));  // crv: P-256
        map.insert(cbor_int(-2), c2pa_cbor::Value::Bytes(vec![0; 32]));
        map.insert(cbor_int(-3), c2pa_cbor::Value::Bytes(vec![0; 32]));

        SessionKeys {
            keys: vec![SessionKey {
                key: c2pa_cbor::Value::Map(map),
                min_sequence_number: 0,
                created_at: DateT(chrono::Utc::now().to_rfc3339()),
                validity_period: 3600,
                signer_binding: c2pa_cbor::Value::Bytes(vec![]),
            }],
        }
    }

    /// Builds an `emsg` version 0 box with C2PA VSI scheme carrying `message_data`.
    #[cfg(feature = "rust_native_crypto")]
    fn make_vsi_emsg_box(message_data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(b"urn:c2pa:verifiable-segment-info\0");
        body.extend_from_slice(b"fseg\0");
        body.extend_from_slice(&[0u8; 16]); // timescale + pts_delta + duration + id
        body.extend_from_slice(message_data);

        let total_size = (8u32 + 4 + body.len() as u32).to_be_bytes();
        let mut emsg = Vec::new();
        emsg.extend_from_slice(&total_size);
        emsg.extend_from_slice(b"emsg");
        emsg.push(0); // version 0
        emsg.extend_from_slice(&[0u8; 3]); // flags
        emsg.extend_from_slice(&body);
        emsg
    }

    // ── 19.4 helpers that require rust_native_crypto (P-256 key generation) ──

    #[cfg(feature = "rust_native_crypto")]
    mod vsi_crypto_helpers {
        use super::*;
        use crate::live_video::verifiable_segment_info::SegmentInfoMap;

        pub const TEST_KID: &[u8] = b"test-key-1";

        pub fn generate_test_key_pair() -> (p256::ecdsa::SigningKey, c2pa_cbor::Value) {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
            let verifying_key = signing_key.verifying_key();
            let point = verifying_key.to_encoded_point(false);

            let mut map = std::collections::BTreeMap::new();
            map.insert(cbor_int(1), cbor_int(2));   // kty: EC2
            map.insert(cbor_int(2), c2pa_cbor::Value::Bytes(TEST_KID.to_vec()));
            map.insert(cbor_int(-1), cbor_int(1));  // crv: P-256
            map.insert(cbor_int(-2), c2pa_cbor::Value::Bytes(point.x().unwrap().to_vec()));
            map.insert(cbor_int(-3), c2pa_cbor::Value::Bytes(point.y().unwrap().to_vec()));

            (signing_key, c2pa_cbor::Value::Map(map))
        }

        pub fn session_keys_with_cose_key(cose_key: c2pa_cbor::Value) -> SessionKeys {
            SessionKeys {
                keys: vec![SessionKey {
                    key: cose_key,
                    min_sequence_number: 0,
                    created_at: DateT(chrono::Utc::now().to_rfc3339()),
                    validity_period: 3600,
                    signer_binding: c2pa_cbor::Value::Bytes(vec![]),
                }],
            }
        }

        pub fn make_signed_cose_sign1_bytes(
            segment_info_map: &SegmentInfoMap,
            signing_key: &p256::ecdsa::SigningKey,
        ) -> Vec<u8> {
            use coset::{iana, HeaderBuilder, TaggedCborSerializable};
            use p256::ecdsa::{signature::Signer, Signature};

            let payload = c2pa_cbor::to_vec(segment_info_map).unwrap();

            let protected = HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .build();

            let unprotected = HeaderBuilder::new()
                .key_id(TEST_KID.to_vec())
                .build();

            let mut sign1 = coset::CoseSign1Builder::new()
                .protected(protected)
                .unprotected(unprotected)
                .payload(payload)
                .build();

            let tbs = sign1.tbs_data(b"");
            let sig: Signature = signing_key.sign(&tbs);
            sign1.signature = sig.to_bytes().to_vec();

            sign1.to_tagged_vec().unwrap()
        }

        pub fn make_signed_vsi_segment(
            sequence_number: u64,
            manifest_id: &str,
            signing_key: &p256::ecdsa::SigningKey,
        ) -> Vec<u8> {
            let map = SegmentInfoMap {
                sequence_number,
                bmff_hash: c2pa_cbor::Value::Null,
                manifest_id: manifest_id.to_string(),
                manifest_uri: None,
            };
            super::make_vsi_emsg_box(&make_signed_cose_sign1_bytes(&map, signing_key))
        }

        pub fn setup_vsi_validator() -> (LiveVideoValidator, p256::ecdsa::SigningKey) {
            let (signing_key, cose_key) = generate_test_key_pair();
            let mut validator = LiveVideoValidator::new();
            let mut tracker = StatusTracker::default();
            let keys = session_keys_with_cose_key(cose_key);
            validator.validate_session_keys(&keys, &mut tracker).unwrap();
            (validator, signing_key)
        }
    }

    // ── 19.4 validate_session_keys tests ──────────────────────────────────────

    #[test]
    fn session_keys_empty_fails() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let _ = validator.validate_session_keys(&SessionKeys { keys: vec![] }, &mut tracker);

        assert!(tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID)
        }));
    }

    #[test]
    fn session_keys_zero_validity_period_fails() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let keys = SessionKeys {
            keys: vec![SessionKey {
                validity_period: 0,
                ..minimal_session_keys().keys.remove(0)
            }],
        };
        let _ = validator.validate_session_keys(&keys, &mut tracker);

        assert!(tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID)
        }));
    }

    #[test]
    fn session_keys_missing_kid_fails() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        // COSE_Key without kid: only kty and crv/x/y, no kid field.
        let mut key_map = std::collections::BTreeMap::new();
        key_map.insert(
            c2pa_cbor::Value::Integer(1),
            c2pa_cbor::Value::Integer(2), // kty: EC2
        );
        let keys = SessionKeys {
            keys: vec![SessionKey {
                key: c2pa_cbor::Value::Map(key_map),
                ..minimal_session_keys().keys.remove(0)
            }],
        };
        let _ = validator.validate_session_keys(&keys, &mut tracker);

        assert!(tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID)
        }));
    }

    #[test]
    fn session_keys_valid_produces_no_errors() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        validator
            .validate_session_keys(&minimal_session_keys(), &mut tracker)
            .unwrap();

        assert!(!tracker.logged_items().iter().any(|i| {
            i.validation_status
                .as_deref()
                .map(|s| s.starts_with("livevideo"))
                .unwrap_or(false)
        }));
    }

    // ── 19.4 validate_verifiable_segment_info tests ───────────────────────────

    #[test]
    fn vsi_without_session_keys_fails() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let _ = validator.validate_verifiable_segment_info(&make_mdat_box(), &mut tracker);

        assert!(tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID)
        }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_segment_without_emsg_fails() {
        let (mut validator, _) = vsi_crypto_helpers::setup_vsi_validator();
        let mut tracker = aggregate_tracker();

        let _ = validator.validate_verifiable_segment_info(&make_mdat_box(), &mut tracker);

        assert!(tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID)
        }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_segment_with_invalid_cose_fails() {
        let (mut validator, _) = vsi_crypto_helpers::setup_vsi_validator();
        let mut tracker = aggregate_tracker();

        let segment = make_vsi_emsg_box(b"not-a-cose-sign1");
        let _ = validator.validate_verifiable_segment_info(&segment, &mut tracker);

        assert!(tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID)
        }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_valid_sequence_advances_state() {
        use vsi_crypto_helpers::*;
        let (mut validator, signing_key) = setup_vsi_validator();
        let mut tracker = aggregate_tracker();

        validator
            .validate_verifiable_segment_info(
                &make_signed_vsi_segment(1, "manifest-1", &signing_key),
                &mut tracker,
            )
            .unwrap();

        validator
            .validate_verifiable_segment_info(
                &make_signed_vsi_segment(2, "manifest-2", &signing_key),
                &mut tracker,
            )
            .unwrap();

        assert!(!tracker.logged_items().iter().any(|i| {
            i.validation_status
                .as_deref()
                .map(|s| s.starts_with("livevideo"))
                .unwrap_or(false)
        }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_regressed_sequence_number_fails() {
        use vsi_crypto_helpers::*;
        let (mut validator, signing_key) = setup_vsi_validator();
        let mut tracker = aggregate_tracker();

        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(5, "m-1", &signing_key),
            &mut tracker,
        );
        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(4, "m-2", &signing_key),
            &mut tracker,
        );

        assert!(tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_ASSERTION_INVALID)
        }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_min_sequence_number_enforced() {
        use vsi_crypto_helpers::*;
        let (signing_key, cose_key) = generate_test_key_pair();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let keys = SessionKeys {
            keys: vec![SessionKey {
                min_sequence_number: 10,
                ..session_keys_with_cose_key(cose_key).keys.remove(0)
            }],
        };
        validator.validate_session_keys(&keys, &mut tracker).unwrap();

        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(5, "m-1", &signing_key),
            &mut tracker,
        );

        assert!(tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID)
        }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_expired_key_fails() {
        use vsi_crypto_helpers::*;
        let (signing_key, cose_key) = generate_test_key_pair();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let keys = SessionKeys {
            keys: vec![SessionKey {
                created_at: DateT("2020-01-01T00:00:00Z".to_string()),
                validity_period: 1,
                ..session_keys_with_cose_key(cose_key).keys.remove(0)
            }],
        };
        validator.validate_session_keys(&keys, &mut tracker).unwrap();

        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(1, "m-1", &signing_key),
            &mut tracker,
        );

        assert!(tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID)
        }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_bad_signature_fails() {
        use vsi_crypto_helpers::*;
        let (_, cose_key) = generate_test_key_pair();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let keys = session_keys_with_cose_key(cose_key);
        validator.validate_session_keys(&keys, &mut tracker).unwrap();

        let (other_key, _) = generate_test_key_pair();
        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(1, "m-1", &other_key),
            &mut tracker,
        );

        assert!(tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID)
        }));
    }
}
