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

//! Support for C2PA Live Video signing and validation (section 19 of the C2PA Technical Specification).
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
//! # Signing
//!
//! Use [`LiveVideoSigner`] to sign an init segment and a sequence of media segments.
//!
//! # Validation
//!
//! Use [`LiveVideoValidator`] to validate a signed live video stream.
//!
//! See [C2PA Technical Specification ��� Live Video](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_live_video).

pub(crate) mod cose_key;
mod segment_manifest_validation;
mod session_key_validation;
pub mod verifiable_segment_info;
mod signing;
mod vsi_signing;

pub use ed25519_dalek::SigningKey as Ed25519SessionKey;
pub use signing::LiveVideoSigner;
pub use vsi_signing::LiveVideoVsiSigner;

use crate::{
    assertions::{LiveVideoSegment, SessionKey, SessionKeys},
    error::{Error, Result},
    log_item,
    status_tracker::StatusTracker,
    validation_results::validation_codes::{
        LIVEVIDEO_INIT_INVALID, LIVEVIDEO_MANIFEST_INVALID, LIVEVIDEO_SESSIONKEY_INVALID,
    },
};

use self::cose_key::kid_from_cose_key;

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
        if segment_manifest_validation::segment_contains_box_type(segment_data, MDAT_BOX_TYPE) {
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

    /// Validates a `c2pa.session-keys` assertion and stores the keys for VSI verification ([§19.4]).
    ///
    /// If `ee_cert_der` is provided (the DER-encoded end-entity certificate from the manifest
    /// signer), each key's `signerBinding` COSE_Sign1 is verified against it ([§19.7.3]).
    /// Callers SHOULD provide the certificate for spec-compliant validation.
    ///
    /// [§19.4]: https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#verifiable_segment_info
    /// [§19.7.3]: https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_verifiable_segment_info_validation
    pub fn validate_session_keys(
        &mut self,
        assertion: &SessionKeys,
        ee_cert_der: Option<&[u8]>,
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

            if let Some(cert) = ee_cert_der {
                self.verify_signer_binding(key, cert, tracker)?;
            }
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
        self.validate_vsi_bmff_hash(
            segment_data,
            &parsed.segment_info_map.bmff_hash,
            tracker,
        )?;

        self.previous_segment = Some(SegmentState {
            sequence_number: seq_num,
            stream_id: String::new(),
            manifest_id: parsed.segment_info_map.manifest_id.clone(),
        });

        Ok(())
    }
}

impl Default for LiveVideoValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test_helpers;
