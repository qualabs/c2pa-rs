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

//! Verifiable Segment Info (VSI) signing for live video (C2PA section 19.4).
//!
//! Each media segment carries a COSE_Sign1 inside an `emsg` box, signed by an
//! Ed25519 session key provided by the caller.  The init segment carries the
//! session key in a `c2pa.session-keys` assertion; the session key's
//! `signerBinding` is a detached COSE_Sign1 where the session key signs the
//! signer's end-entity certificate, proving the key is associated with the
//! manifest signer (§18.25.2).

use std::collections::BTreeMap;

use coset::{iana, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey, VerifyingKey};

use crate::{
    assertions::{BmffHash, DataMap, ExclusionsMap, SessionKey, SessionKeys},
    builder::Builder,
    cbor_types::DateT,
    error::{Error, Result},
    live_video::verifiable_segment_info::SegmentInfoMap,
    Reader, Signer,
};

const VSI_SCHEME_ID_URI: &str = "urn:c2pa:verifiable-segment-info";
const VSI_VALUE_FSEG: &str = "fseg";

/// Signs live video segments using the Verifiable Segment Info method (§19.4).
///
/// The caller provides an Ed25519 session key via [`from_signing_key`].  The
/// init segment is signed with the manifest [`Signer`] and carries a
/// `c2pa.session-keys` assertion that includes the session public key and a
/// `signerBinding` COSE_Sign1 proving the key is associated with the manifest
/// signer.
///
/// Each media segment receives a COSE_Sign1 `emsg` box signed by the session
/// key; the box is prepended to the segment bytes.
///
/// [`from_signing_key`]: LiveVideoVsiSigner::from_signing_key
pub struct LiveVideoVsiSigner {
    session_signing_key: SigningKey,
    session_cose_key: c2pa_cbor::Value,
    kid: Vec<u8>,
    signer_binding: c2pa_cbor::Value,
    min_sequence_number: u64,
    created_at: DateT,
    validity_period: u64,
    next_sequence_number: u64,
    base_manifest_json: String,
    /// Instance ID of the active manifest from the signed init segment.
    /// Populated by `sign_init_segment` and embedded in every media segment's
    /// `segment-info-map` as `manifestId` per §19.4.
    active_manifest_id: Option<String>,
}

impl LiveVideoVsiSigner {
    /// Creates a VSI signer from a caller-provided Ed25519 session key.
    ///
    /// Builds the `signerBinding` COSE_Sign1 per §18.25.2: the session key
    /// signs the manifest signer's end-entity certificate (detached payload).
    ///
    /// # Arguments
    ///
    /// * `manifest_json` — base manifest JSON (without a `c2pa.session-keys`
    ///   assertion; one is added automatically when signing the init segment).
    /// * `manifest_signer` — the C2PA [`Signer`] whose end-entity certificate
    ///   is bound to the session key via `signerBinding`.
    /// * `signing_key` — Ed25519 session private key.
    /// * `kid` — key identifier for the session key (e.g. `b"session-key-1"`).
    /// * `min_sequence_number` — first sequence number valid for this key.
    /// * `validity_period_secs` — how long (in seconds) the session key is valid.
    pub fn from_signing_key(
        manifest_json: impl Into<String>,
        manifest_signer: &dyn Signer,
        signing_key: SigningKey,
        kid: impl Into<Vec<u8>>,
        min_sequence_number: u64,
        validity_period_secs: u64,
    ) -> Result<Self> {
        let base_manifest_json = manifest_json.into();
        let kid = kid.into();

        let session_cose_key = build_ed25519_cose_key(&signing_key.verifying_key(), &kid);

        let ee_cert_der = manifest_signer
            .certs()
            .map_err(|e| Error::OtherError(Box::new(e)))?
            .into_iter()
            .next()
            .ok_or_else(|| Error::BadParam("manifest signer has no certificates".into()))?;

        let signer_binding = build_signer_binding(
            &ee_cert_der,
            &signing_key,
        )?;

        let created_at = DateT(chrono::Utc::now().to_rfc3339());

        Ok(Self {
            session_signing_key: signing_key,
            session_cose_key,
            kid,
            signer_binding,
            min_sequence_number,
            created_at,
            validity_period: validity_period_secs,
            next_sequence_number: min_sequence_number,
            base_manifest_json,
            active_manifest_id: None,
        })
    }

    /// Signs an init segment, embedding a `c2pa.session-keys` assertion.
    ///
    /// Captures the manifest instance ID from the signed output so that
    /// subsequent calls to [`sign_media_segment`] can embed it as `manifestId`
    /// per §19.4.
    ///
    /// Per §19.2.3, the init segment SHOULD NOT contain media data (`mdat`).
    ///
    /// [`sign_media_segment`]: LiveVideoVsiSigner::sign_media_segment
    pub fn sign_init_segment(
        &mut self,
        segment_data: &[u8],
        format: &str,
        manifest_signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        let session_keys = self.build_session_keys_assertion();
        let mut builder = Builder::from_json(&self.base_manifest_json)?;
        builder.add_assertion_cbor(SessionKeys::LABEL, &session_keys)?;

        let mut source = std::io::Cursor::new(segment_data);
        let mut dest = std::io::Cursor::new(Vec::new());
        builder.sign(manifest_signer, format, &mut source, &mut dest)?;
        let signed_bytes = dest.into_inner();

        // Capture the manifest ID so media segments can reference it as `manifestId`.
        // c2pa-rs stores instance IDs as "xmp:iid:{uuid}"; convert to the canonical
        // "urn:uuid:{uuid}" form required by the C2PA VSI spec §19.4.
        let reader = Reader::from_stream(format, std::io::Cursor::new(&signed_bytes))?;
        if let Some(manifest) = reader.active_manifest() {
            let raw_id = manifest.instance_id();
            let canonical_id = raw_id
                .strip_prefix("xmp:iid:")
                .map(|uuid| format!("urn:uuid:{uuid}"))
                .unwrap_or_else(|| raw_id.to_string());
            self.active_manifest_id = Some(canonical_id);
        }

        Ok(signed_bytes)
    }

    /// Signs a media segment by prepending a COSE_Sign1 `emsg` box.
    ///
    /// The COSE_Sign1 payload is a CBOR `SegmentInfoMap` with the current
    /// sequence number, a `bmffHash` covering the segment data excluding VSI
    /// `emsg` boxes, and the `manifestId` from the signed init segment per §19.4.
    pub fn sign_media_segment(&mut self, segment_data: &[u8]) -> Result<Vec<u8>> {
        let bmff_hash = build_segment_bmff_hash(segment_data)?;
        let manifest_id = self.active_manifest_id.clone().unwrap_or_default();

        let segment_info_map = SegmentInfoMap {
            sequence_number: self.next_sequence_number,
            bmff_hash,
            manifest_id,
            manifest_uri: None,
        };

        let cose_sign1_bytes = build_vsi_cose_sign1(&segment_info_map, &self.session_signing_key, &self.kid)?;
        let emsg_box = build_emsg_box(&cose_sign1_bytes);

        let mut signed_segment = emsg_box;
        signed_segment.extend_from_slice(segment_data);

        self.next_sequence_number += 1;
        Ok(signed_segment)
    }

    /// Returns the sequence number assigned to the next media segment.
    pub fn next_sequence_number(&self) -> u64 {
        self.next_sequence_number
    }

    /// Restores the active manifest ID from a previously signed init segment.
    ///
    /// Used when resuming a live session across process invocations.  Re-signing
    /// the init would produce a different UUID, breaking `manifestId` continuity
    /// across segments.  Instead, call this method with the already-signed init
    /// from the output directory to restore the session's `manifestId`.
    pub fn restore_manifest_id_from_signed_init(
        &mut self,
        signed_init_data: &[u8],
        format: &str,
    ) -> Result<()> {
        let reader = Reader::from_stream(format, std::io::Cursor::new(signed_init_data))?;
        if let Some(manifest) = reader.active_manifest() {
            let raw_id = manifest.instance_id();
            let canonical_id = raw_id
                .strip_prefix("xmp:iid:")
                .map(|uuid| format!("urn:uuid:{uuid}"))
                .unwrap_or_else(|| raw_id.to_string());
            self.active_manifest_id = Some(canonical_id);
        }
        Ok(())
    }

    /// Resumes from a previously signed VSI segment.
    ///
    /// Extracts the `sequenceNumber` from the segment's `emsg` box and sets
    /// `next_sequence_number` to `sequenceNumber + 1`.
    pub fn resume_from_segment(&mut self, segment_data: &[u8]) -> Result<()> {
        use crate::live_video::verifiable_segment_info::{extract_vsi_payload_from_segment, parse_vsi};

        let vsi_bytes = extract_vsi_payload_from_segment(segment_data)
            .ok_or_else(|| Error::BadParam(
                "previous segment does not contain a VSI emsg box".into(),
            ))?;

        let parsed = parse_vsi(&vsi_bytes)?;
        self.next_sequence_number = parsed.segment_info_map.sequence_number + 1;
        Ok(())
    }

    fn build_session_keys_assertion(&self) -> SessionKeys {
        SessionKeys {
            keys: vec![SessionKey {
                key: self.session_cose_key.clone(),
                min_sequence_number: self.min_sequence_number,
                created_at: self.created_at.clone(),
                validity_period: self.validity_period,
                signer_binding: self.signer_binding.clone(),
            }],
        }
    }
}

// ── BMFF hash helper ─────────────────────────────────────────────────────────

/// Computes the `bmff-hash-map` for a media segment per §19.4.1.
///
/// The hash covers the entire segment excluding any VSI `emsg` boxes, identified
/// by their `scheme_id_uri` field ("urn:c2pa:verifiable-segment-info").  The
/// exclusion `offset` is 12 because in an ISO BMFF `emsg` box the
/// `scheme_id_uri` string starts at byte 12 from the box start (8-byte BMFF
/// header + 4-byte FullBox version/flags header).
///
/// `bmff_version` is forced to 0 to match what the validator sees after a
/// CBOR round-trip, since `BmffHash::bmff_version` is `#[serde(skip)]` and
/// therefore deserializes as 0.
fn build_segment_bmff_hash(segment_data: &[u8]) -> Result<c2pa_cbor::Value> {
    const VSI_URI_OFFSET_IN_EMSG: u64 = 12;

    let mut bmff_hash = BmffHash::new("jumbf manifest", "sha256", None);
    bmff_hash.set_bmff_version(0);

    let mut vsi_emsg_exclusion = ExclusionsMap::new("/emsg".to_string());
    vsi_emsg_exclusion.data = Some(vec![DataMap {
        offset: VSI_URI_OFFSET_IN_EMSG,
        value: VSI_SCHEME_ID_URI.as_bytes().to_vec(),
    }]);
    bmff_hash.add_exclusions(&mut vec![vsi_emsg_exclusion]);

    let mut cursor = std::io::Cursor::new(segment_data);
    bmff_hash
        .gen_hash_from_stream(&mut cursor)
        .map_err(|e| Error::BadParam(format!("failed to compute segment bmffHash: {e}")))?;

    c2pa_cbor::value::to_value(&bmff_hash)
        .map_err(|e| Error::BadParam(format!("failed to serialize bmffHash to CBOR: {e}")))
}

// ── Ed25519 helpers ──────────────────────────────────────────────────────────

pub(super) fn build_ed25519_cose_key(verifying_key: &VerifyingKey, kid: &[u8]) -> c2pa_cbor::Value {
    // OKP COSE_Key for Ed25519 (RFC 9052):
    //   1 (kty)  → 1 (OKP)
    //   2 (kid)  → bytes
    //   3 (alg)  → -8 (EdDSA)
    //  -1 (crv)  → 6 (Ed25519)
    //  -2 (x)   → public key bytes (32 bytes)
    let mut map = BTreeMap::new();
    map.insert(c2pa_cbor::Value::Integer(1), c2pa_cbor::Value::Integer(1));   // kty: OKP
    map.insert(c2pa_cbor::Value::Integer(2), c2pa_cbor::Value::Bytes(kid.to_vec()));   // kid
    map.insert(c2pa_cbor::Value::Integer(3), c2pa_cbor::Value::Integer(-8));  // alg: EdDSA
    map.insert(c2pa_cbor::Value::Integer(-1), c2pa_cbor::Value::Integer(6));  // crv: Ed25519
    map.insert(c2pa_cbor::Value::Integer(-2), c2pa_cbor::Value::Bytes(verifying_key.as_bytes().to_vec())); // x
    c2pa_cbor::Value::Map(map)
}

// ── Signer binding (§18.25.2) ────────────────────────────────────────────────
//
// Per the spec the `signerBinding` is a **detached** COSE_Sign1 where:
//   - the **session key** signs (EdDSA since we use Ed25519),
//   - the **payload** is the signer's end-entity certificate encoded as a CBOR
//     byte string (used in Sig_structure but NOT carried in the COSE_Sign1).

fn build_signer_binding(
    ee_cert_der: &[u8],
    session_signing_key: &SigningKey,
) -> Result<c2pa_cbor::Value> {
    let external_payload = c2pa_cbor::to_vec(&c2pa_cbor::Value::Bytes(ee_cert_der.to_vec()))
        .map_err(|e| Error::BadParam(format!("failed to CBOR-encode EE certificate: {e}")))?;

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .build();

    let mut sign1 = CoseSign1Builder::new()
        .protected(protected)
        .build();

    // signerBinding is a detached-payload COSE_Sign1: the cert bytes are the
    // external payload, not AAD. Use tbs_detached_data per RFC 9052 §4.4.
    let tbs = sign1.tbs_detached_data(&external_payload, b"");
    let signature: ed25519_dalek::Signature = Ed25519Signer::sign(session_signing_key, &tbs);
    sign1.signature = signature.to_bytes().to_vec();

    let binding_bytes = sign1
        .to_tagged_vec()
        .map_err(|e| Error::BadParam(format!("failed to encode signer binding: {e}")))?;

    // Deserialize back to a Value so the COSE_Sign1 is embedded as a tagged
    // CBOR structure (tag 18) rather than an opaque bstr.
    c2pa_cbor::from_slice(&binding_bytes)
        .map_err(|e| Error::BadParam(format!("failed to decode signer binding as CBOR Value: {e}")))
}

// ── VSI COSE_Sign1 construction ──────────────────────────────────────────────

fn build_vsi_cose_sign1(
    segment_info_map: &SegmentInfoMap,
    signing_key: &SigningKey,
    kid: &[u8],
) -> Result<Vec<u8>> {
    let payload = c2pa_cbor::to_vec(segment_info_map)
        .map_err(|e| Error::BadParam(format!("failed to encode SegmentInfoMap: {e}")))?;

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .build();
    let unprotected = HeaderBuilder::new().key_id(kid.to_vec()).build();

    let mut sign1 = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(payload)
        .build();

    let tbs = sign1.tbs_data(b"");
    let signature: ed25519_dalek::Signature = signing_key.sign(&tbs);
    sign1.signature = signature.to_bytes().to_vec();

    sign1
        .to_tagged_vec()
        .map_err(|e| Error::BadParam(format!("failed to encode COSE_Sign1: {e}")))
}

// ── emsg box construction ────────────────────────────────────────────────────

fn build_emsg_box(cose_sign1_bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(VSI_SCHEME_ID_URI.as_bytes());
    body.push(0); // null terminator
    body.extend_from_slice(VSI_VALUE_FSEG.as_bytes());
    body.push(0); // null terminator
    body.extend_from_slice(&[0u8; 16]); // timescale + presentation_time_delta + event_duration + id
    body.extend_from_slice(cose_sign1_bytes);

    // 8 bytes header + 4 bytes version/flags + body
    let total_size = (8u32 + 4 + body.len() as u32).to_be_bytes();

    let mut emsg = Vec::new();
    emsg.extend_from_slice(&total_size);
    emsg.extend_from_slice(b"emsg");
    emsg.push(0); // version 0
    emsg.extend_from_slice(&[0u8; 3]); // flags
    emsg.extend_from_slice(&body);
    emsg
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{
        live_video::{
            verifiable_segment_info::extract_vsi_payload_from_segment, LiveVideoValidator,
        },
        status_tracker::StatusTracker,
        utils::ephemeral_signer::EphemeralSigner,
    };

    fn make_test_segment() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&8u32.to_be_bytes());
        data.extend_from_slice(b"mdat");
        data
    }

    fn make_test_signer() -> EphemeralSigner {
        EphemeralSigner::new("test-vsi.local").unwrap()
    }

    fn make_test_signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    fn make_vsi_signer(
        signer: &EphemeralSigner,
        kid: &[u8],
        min_seq: u64,
    ) -> LiveVideoVsiSigner {
        LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            signer,
            make_test_signing_key(),
            kid.to_vec(),
            min_seq,
            3600,
        )
        .unwrap()
    }

    #[test]
    fn sign_media_segment_prepends_emsg_box() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"key-1", 1);

        let segment = make_test_segment();
        let signed = vsi_signer.sign_media_segment(&segment).unwrap();

        assert!(signed.len() > segment.len());

        let vsi_payload = extract_vsi_payload_from_segment(&signed);
        assert!(vsi_payload.is_some(), "VSI emsg payload not found in signed segment");
    }

    #[test]
    fn sequence_numbers_advance_per_segment() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"k", 1);

        assert_eq!(vsi_signer.next_sequence_number(), 1);

        vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        assert_eq!(vsi_signer.next_sequence_number(), 2);

        vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        assert_eq!(vsi_signer.next_sequence_number(), 3);
    }

    #[test]
    fn signed_segment_passes_vsi_validation() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"key-1", 1);

        let session_keys = vsi_signer.build_session_keys_assertion();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();

        validator
            .validate_session_keys(&session_keys, None, &mut tracker)
            .unwrap();

        let segment = vsi_signer
            .sign_media_segment(&make_test_segment())
            .unwrap();

        validator
            .validate_verifiable_segment_info(&segment, &mut tracker)
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
        assert!(failures.is_empty(), "unexpected validation failures: {failures:?}");
    }

    #[test]
    fn vsi_payload_contains_correct_sequence_number() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"k", 5);

        let signed = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        let vsi_bytes = extract_vsi_payload_from_segment(&signed).unwrap();
        let info_map = parse_segment_info_map(&vsi_bytes).unwrap();

        assert_eq!(info_map.sequence_number, 5);
    }

    #[test]
    fn signer_binding_roundtrip_validates() {
        let signer = make_test_signer();
        let vsi_signer = make_vsi_signer(&signer, b"key-1", 1);

        let session_keys = vsi_signer.build_session_keys_assertion();
        let ee_cert_der = signer.certs().unwrap().into_iter().next().unwrap();

        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();

        validator
            .validate_session_keys(&session_keys, Some(&ee_cert_der), &mut tracker)
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
        assert!(
            failures.is_empty(),
            "signerBinding validation failures: {failures:?}"
        );
    }

    #[test]
    fn second_segment_has_next_sequence_number() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"k", 1);

        let seg1 = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        let seg2 = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();

        let map1 = parse_segment_info_map(&extract_vsi_payload_from_segment(&seg1).unwrap()).unwrap();
        let map2 = parse_segment_info_map(&extract_vsi_payload_from_segment(&seg2).unwrap()).unwrap();

        assert_eq!(map1.sequence_number, 1);
        assert_eq!(map2.sequence_number, 2);
    }

    #[test]
    fn resume_from_segment_advances_sequence_number() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"k", 1);

        let seg1 = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        assert_eq!(vsi_signer.next_sequence_number(), 2);

        let mut resumed_signer = make_vsi_signer(&signer, b"k", 1);
        resumed_signer.resume_from_segment(&seg1).unwrap();
        assert_eq!(resumed_signer.next_sequence_number(), 2);
    }

    #[test]
    fn sign_media_segment_bmff_hash_is_not_null() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"k", 1);

        let signed = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        let vsi_bytes = extract_vsi_payload_from_segment(&signed).unwrap();
        let info_map = parse_segment_info_map(&vsi_bytes).unwrap();

        assert!(
            !info_map.bmff_hash.is_null(),
            "bmffHash must not be null per §19.4 — regression guard"
        );
    }

    #[test]
    fn sign_media_segment_manifest_id_empty_without_init() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"k", 1);

        let signed = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        let vsi_bytes = extract_vsi_payload_from_segment(&signed).unwrap();
        let info_map = parse_segment_info_map(&vsi_bytes).unwrap();

        // When sign_init_segment has not been called, manifest_id defaults to empty.
        assert_eq!(info_map.manifest_id, "");
    }

    #[test]
    fn sign_media_segment_manifest_id_populated_after_signing_init() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        // Use a real DASH init segment so Builder::sign can embed the manifest.
        let init_data = include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");

        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"k", 1);

        vsi_signer
            .sign_init_segment(init_data, "video/mp4", &signer)
            .unwrap();

        let signed = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        let vsi_bytes = extract_vsi_payload_from_segment(&signed).unwrap();
        let info_map = parse_segment_info_map(&vsi_bytes).unwrap();

        assert!(
            !info_map.manifest_id.is_empty(),
            "manifestId must be populated from the signed init segment per §19.4"
        );
    }

    #[test]
    fn resume_from_segment_enables_continued_signing() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        let signer = make_test_signer();
        let session_key = make_test_signing_key();

        let mut signer1 = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            session_key.clone(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        let seg1 = signer1.sign_media_segment(&make_test_segment()).unwrap();

        let mut signer2 = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            session_key.clone(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        signer2.resume_from_segment(&seg1).unwrap();
        let seg2 = signer2.sign_media_segment(&make_test_segment()).unwrap();

        let map1 = parse_segment_info_map(&extract_vsi_payload_from_segment(&seg1).unwrap()).unwrap();
        let map2 = parse_segment_info_map(&extract_vsi_payload_from_segment(&seg2).unwrap()).unwrap();
        assert_eq!(map1.sequence_number, 1);
        assert_eq!(map2.sequence_number, 2);

        let session_keys = signer2.build_session_keys_assertion();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator.validate_session_keys(&session_keys, None, &mut tracker).unwrap();

        validator.validate_verifiable_segment_info(&seg1, &mut tracker).unwrap();
        validator.validate_verifiable_segment_info(&seg2, &mut tracker).unwrap();

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
        assert!(failures.is_empty(), "validation failures: {failures:?}");
    }

    /// Regression test for the dynamic-manifestId bug: when the CLI is invoked once per
    /// segment (live session), `sign_init_segment` must not be called again.
    /// Instead, `restore_manifest_id_from_signed_init` must produce the same `manifestId`
    /// as the original `sign_init_segment` call.
    #[test]
    fn restore_manifest_id_from_signed_init_matches_original_manifest_id() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        let init_data = include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");

        let signer = make_test_signer();
        let session_key = make_test_signing_key();

        // Simulate first CLI invocation: sign init + seg_001.
        let mut signer_call1 = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            session_key.clone(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        let signed_init = signer_call1
            .sign_init_segment(init_data, "video/mp4", &signer)
            .unwrap();
        let seg1 = signer_call1.sign_media_segment(&make_test_segment()).unwrap();
        let map1 = parse_segment_info_map(
            &extract_vsi_payload_from_segment(&seg1).unwrap()
        ).unwrap();

        // Simulate second CLI invocation: new signer process, restore state.
        let mut signer_call2 = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            session_key.clone(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        signer_call2.resume_from_segment(&seg1).unwrap();
        signer_call2
            .restore_manifest_id_from_signed_init(&signed_init, "video/mp4")
            .unwrap();
        let seg2 = signer_call2.sign_media_segment(&make_test_segment()).unwrap();
        let map2 = parse_segment_info_map(
            &extract_vsi_payload_from_segment(&seg2).unwrap()
        ).unwrap();

        // Both segments must reference the same manifestId.
        assert_eq!(
            map1.manifest_id, map2.manifest_id,
            "manifestId must be identical across per-segment invocations (§19.4)"
        );
        assert!(
            map2.manifest_id.starts_with("urn:uuid:"),
            "manifestId must use urn:uuid: prefix, got: {}",
            map2.manifest_id
        );
        assert_eq!(map1.sequence_number, 1);
        assert_eq!(map2.sequence_number, 2);
    }
}
