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
    assertions::{SessionKey, SessionKeys},
    builder::Builder,
    cbor_types::DateT,
    error::{Error, Result},
    live_video::verifiable_segment_info::SegmentInfoMap,
    Signer,
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
        })
    }

    /// Signs an init segment, embedding a `c2pa.session-keys` assertion.
    ///
    /// Per §19.2.3, the init segment SHOULD NOT contain media data (`mdat`).
    pub fn sign_init_segment(
        &self,
        segment_data: &[u8],
        format: &str,
        manifest_signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        let session_keys = self.build_session_keys_assertion();
        let mut builder = Builder::from_json(&self.base_manifest_json)?;
        builder.add_assertion(SessionKeys::LABEL, &session_keys)?;

        let mut source = std::io::Cursor::new(segment_data);
        let mut dest = std::io::Cursor::new(Vec::new());
        builder.sign(manifest_signer, format, &mut source, &mut dest)?;
        Ok(dest.into_inner())
    }

    /// Signs a media segment by prepending a COSE_Sign1 `emsg` box.
    ///
    /// The COSE_Sign1 payload is a CBOR `SegmentInfoMap` with the current
    /// sequence number.  The box is signed with the session Ed25519 key.
    pub fn sign_media_segment(&mut self, segment_data: &[u8]) -> Result<Vec<u8>> {
        let segment_info_map = SegmentInfoMap {
            sequence_number: self.next_sequence_number,
            bmff_hash: c2pa_cbor::Value::Null,
            manifest_id: String::new(),
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

// ── Ed25519 helpers ──────────────────────────────────────────────────────────

fn build_ed25519_cose_key(verifying_key: &VerifyingKey, kid: &[u8]) -> c2pa_cbor::Value {
    // OKP COSE_Key for Ed25519:
    //   1 (kty)  → 1 (OKP)
    //   2 (kid)  → bytes
    //  -1 (crv)  → 6 (Ed25519)
    //  -2 (x)   → public key bytes (32 bytes)
    let mut map = BTreeMap::new();
    map.insert(c2pa_cbor::Value::Integer(1), c2pa_cbor::Value::Integer(1));  // kty: OKP
    map.insert(c2pa_cbor::Value::Integer(2), c2pa_cbor::Value::Bytes(kid.to_vec()));  // kid
    map.insert(c2pa_cbor::Value::Integer(-1), c2pa_cbor::Value::Integer(6)); // crv: Ed25519
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

    let tbs = sign1.tbs_data(&external_payload);
    let signature: ed25519_dalek::Signature = Ed25519Signer::sign(session_signing_key, &tbs);
    sign1.signature = signature.to_bytes().to_vec();

    let binding_bytes = sign1
        .to_tagged_vec()
        .map_err(|e| Error::BadParam(format!("failed to encode signer binding: {e}")))?;

    Ok(c2pa_cbor::Value::Bytes(binding_bytes))
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
}
