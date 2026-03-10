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

use crate::{
    assertions::SessionKey,
    crypto::{cose::signing_alg_from_sign1, raw_signature::validator_for_signing_alg},
    error::{Error, Result},
    status_tracker::StatusTracker,
    validation_results::validation_codes::{
        LIVEVIDEO_ASSERTION_INVALID, LIVEVIDEO_SEGMENT_INVALID, LIVEVIDEO_SESSIONKEY_INVALID,
    },
};

use coset::TaggedCborSerializable;

use super::{
    cose_key::{cose_key_to_der, kid_from_cose_key, signing_alg_from_cose_key},
    fail_validation,
    verifiable_segment_info::{extract_vsi_payload_from_segment, parse_vsi, ParsedVsi},
    LiveVideoValidator,
};

impl LiveVideoValidator {
    pub(super) fn require_session_keys(&self, tracker: &mut StatusTracker) -> Result<()> {
        if self.session_keys.is_empty() {
            return fail_validation(
                "no session keys available; validate_session_keys must be called first",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }
        Ok(())
    }

    pub(super) fn extract_and_parse_vsi(
        &self,
        segment_data: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<ParsedVsi> {
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

    pub(super) fn resolve_session_key(
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

    pub(super) fn validate_vsi_sequence_bounds(
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

    pub(super) fn validate_vsi_key_validity(
        &self,
        session_key: &SessionKey,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if let Err(msg) = self.check_key_validity_period(session_key) {
            return fail_validation(msg, LIVEVIDEO_SESSIONKEY_INVALID, tracker);
        }
        Ok(())
    }

    pub(super) fn validate_vsi_signature(
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

    pub(super) fn validate_vsi_sequence_continuity(
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

    /// Verifies the segment's BMFF hash against the `bmffHash` in the segment-info-map (§19.7.3).
    ///
    /// If the `bmffHash` field is `Null`, verification is skipped.
    pub(super) fn validate_vsi_bmff_hash(
        &self,
        segment_data: &[u8],
        bmff_hash_value: &c2pa_cbor::Value,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if bmff_hash_value.is_null() {
            return Ok(());
        }

        let bmff_hash: crate::assertions::BmffHash =
            match c2pa_cbor::value::from_value(bmff_hash_value.clone()) {
                Ok(h) => h,
                Err(e) => {
                    return fail_validation(
                        format!("failed to deserialize bmffHash from segment-info-map: {e}"),
                        LIVEVIDEO_SEGMENT_INVALID,
                        tracker,
                    );
                }
            };

        if let Err(e) = bmff_hash.verify_in_memory_hash(segment_data, None) {
            return fail_validation(
                format!("segment bmffHash verification failed: {e}"),
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }

        Ok(())
    }

    fn find_session_key_by_kid(&self, kid: &[u8]) -> Option<SessionKey> {
        self.session_keys
            .iter()
            .find(|sk| {
                kid_from_cose_key(&sk.key)
                    .map(|k| k == kid)
                    .unwrap_or(false)
            })
            .cloned()
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

    /// Verifies the `signerBinding` COSE_Sign1 on a session key against the manifest signer's
    /// end-entity certificate (§19.7.3).
    pub(super) fn verify_signer_binding(
        &self,
        key: &SessionKey,
        ee_cert_der: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        let binding_bytes = extract_signer_binding_bytes(&key.signer_binding);
        let binding_bytes = match binding_bytes {
            Some(ref b) if !b.is_empty() => b,
            _ => {
                return fail_validation(
                    "session key signerBinding must be a non-empty COSE_Sign1_Tagged byte string",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }
        };

        let sign1 = match coset::CoseSign1::from_tagged_slice(binding_bytes) {
            Ok(s) => s,
            Err(e) => {
                return fail_validation(
                    format!("failed to parse signerBinding as COSE_Sign1: {e}"),
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }
        };

        let alg = match signing_alg_from_sign1(&sign1) {
            Ok(a) => a,
            Err(_) => {
                return fail_validation(
                    "signerBinding COSE_Sign1 has unsupported or missing algorithm",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }
        };

        let spki_der = match spki_der_from_cert(ee_cert_der) {
            Some(spki) => spki,
            None => {
                return fail_validation(
                    "failed to extract public key from end-entity certificate",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }
        };

        let validator = match validator_for_signing_alg(alg) {
            Some(v) => v,
            None => {
                return fail_validation(
                    format!("no signature validator available for {alg:?}"),
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }
        };

        let tbs = sign1.tbs_data(b"");
        if let Err(e) = validator.validate(&sign1.signature, &tbs, &spki_der) {
            return fail_validation(
                format!("signerBinding signature verification failed: {e}"),
                LIVEVIDEO_SESSIONKEY_INVALID,
                tracker,
            );
        }

        Ok(())
    }
}

fn spki_der_from_cert(cert_der: &[u8]) -> Option<Vec<u8>> {
    use asn1_rs::FromDer;
    use x509_parser::prelude::X509Certificate;

    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    Some(cert.public_key().raw.to_vec())
}

/// Extracts raw bytes from a `signerBinding` CBOR value.
///
/// The value may appear in different forms depending on the serialization roundtrip:
/// - `Value::Bytes` — direct CBOR byte string (ideal case)
/// - `Value::Text` — base64-encoded string (serde_json with base64 for bytes)
/// - `Value::Array` of integers — JSON array representation of bytes
fn extract_signer_binding_bytes(value: &c2pa_cbor::Value) -> Option<Vec<u8>> {
    match value {
        c2pa_cbor::Value::Bytes(bytes) => Some(bytes.clone()),
        c2pa_cbor::Value::Text(text) => {
            use base64::{engine::general_purpose, Engine};
            general_purpose::STANDARD
                .decode(text)
                .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(text))
                .ok()
        }
        c2pa_cbor::Value::Array(items) => items
            .iter()
            .map(|v| match v {
                c2pa_cbor::Value::Integer(i) => u8::try_from(*i).ok(),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::super::{test_helpers::*, LiveVideoValidator};
    use crate::{
        assertions::{SessionKey, SessionKeys},
        cbor_types::DateT,
        validation_results::validation_codes::{
            LIVEVIDEO_SEGMENT_INVALID, LIVEVIDEO_SESSIONKEY_INVALID,
        },
    };

    fn cbor_int(val: i64) -> c2pa_cbor::Value {
        c2pa_cbor::Value::Integer(val)
    }

    fn minimal_session_keys() -> SessionKeys {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(1), cbor_int(2)); // kty: EC2
        map.insert(
            cbor_int(2),
            c2pa_cbor::Value::Bytes(b"k".to_vec()),
        ); // kid
        map.insert(cbor_int(-1), cbor_int(1)); // crv: P-256
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

    #[cfg(feature = "rust_native_crypto")]
    mod vsi_crypto_helpers {
        use super::*;
        use crate::{
            live_video::verifiable_segment_info::SegmentInfoMap, status_tracker::StatusTracker,
        };

        pub const TEST_KID: &[u8] = b"test-key-1";

        pub fn generate_test_key_pair() -> (p256::ecdsa::SigningKey, c2pa_cbor::Value) {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
            let verifying_key = signing_key.verifying_key();
            let point = verifying_key.to_encoded_point(false);

            let mut map = std::collections::BTreeMap::new();
            map.insert(cbor_int(1), cbor_int(2)); // kty: EC2
            map.insert(
                cbor_int(2),
                c2pa_cbor::Value::Bytes(TEST_KID.to_vec()),
            );
            map.insert(cbor_int(-1), cbor_int(1)); // crv: P-256
            map.insert(
                cbor_int(-2),
                c2pa_cbor::Value::Bytes(point.x().unwrap().to_vec()),
            );
            map.insert(
                cbor_int(-3),
                c2pa_cbor::Value::Bytes(point.y().unwrap().to_vec()),
            );

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

            let unprotected = HeaderBuilder::new().key_id(TEST_KID.to_vec()).build();

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
            validator
                .validate_session_keys(&keys, None, &mut tracker)
                .unwrap();
            (validator, signing_key)
        }
    }

    // ── validate_session_keys ─────────────────────────────────────────────────

    #[test]
    fn session_keys_empty_fails() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let _ = validator.validate_session_keys(&SessionKeys { keys: vec![] }, None, &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
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
        let _ = validator.validate_session_keys(&keys, None, &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
    }

    #[test]
    fn session_keys_missing_kid_fails() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

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
        let _ = validator.validate_session_keys(&keys, None, &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
    }

    #[test]
    fn session_keys_valid_produces_no_errors() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        validator
            .validate_session_keys(&minimal_session_keys(), None, &mut tracker)
            .unwrap();

        assert!(!tracker.logged_items().iter().any(|i| {
            i.validation_status
                .as_deref()
                .map(|s| s.starts_with("livevideo"))
                .unwrap_or(false)
        }));
    }

    // ── validate_verifiable_segment_info ───────────────────────────────────────

    #[test]
    fn vsi_without_session_keys_fails() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let _ = validator.validate_verifiable_segment_info(&make_mdat_box(), &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_segment_without_emsg_fails() {
        let (mut validator, _) = vsi_crypto_helpers::setup_vsi_validator();
        let mut tracker = aggregate_tracker();

        let _ = validator.validate_verifiable_segment_info(&make_mdat_box(), &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_segment_with_invalid_cose_fails() {
        let (mut validator, _) = vsi_crypto_helpers::setup_vsi_validator();
        let mut tracker = aggregate_tracker();

        let segment = make_vsi_emsg_box(b"not-a-cose-sign1");
        let _ = validator.validate_verifiable_segment_info(&segment, &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
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
        use crate::validation_results::validation_codes::LIVEVIDEO_ASSERTION_INVALID;
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

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_ASSERTION_INVALID) }));
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
        validator
            .validate_session_keys(&keys, None, &mut tracker)
            .unwrap();

        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(5, "m-1", &signing_key),
            &mut tracker,
        );

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
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
        validator
            .validate_session_keys(&keys, None, &mut tracker)
            .unwrap();

        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(1, "m-1", &signing_key),
            &mut tracker,
        );

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
    }

    #[cfg(feature = "rust_native_crypto")]
    #[test]
    fn vsi_bad_signature_fails() {
        use vsi_crypto_helpers::*;
        let (_, cose_key) = generate_test_key_pair();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let keys = session_keys_with_cose_key(cose_key);
        validator
            .validate_session_keys(&keys, None, &mut tracker)
            .unwrap();

        let (other_key, _) = generate_test_key_pair();
        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(1, "m-1", &other_key),
            &mut tracker,
        );

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    // ── signer_binding verification ────────────────────────────────────────────

    fn make_signer_binding_cose(signer: &dyn crate::Signer) -> Vec<u8> {
        use coset::{iana, HeaderBuilder, TaggedCborSerializable};

        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .build();
        let mut sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .payload(b"session-key-binding".to_vec())
            .build();
        let tbs = sign1.tbs_data(b"");
        sign1.signature = signer.sign(&tbs).unwrap();
        sign1.to_tagged_vec().unwrap()
    }

    fn session_key_with_binding(binding_bytes: Vec<u8>) -> SessionKeys {
        let mut key_map = std::collections::BTreeMap::new();
        key_map.insert(cbor_int(1), cbor_int(2)); // kty: EC2
        key_map.insert(
            cbor_int(2),
            c2pa_cbor::Value::Bytes(b"k".to_vec()),
        ); // kid
        key_map.insert(cbor_int(-1), cbor_int(1)); // crv: P-256
        key_map.insert(cbor_int(-2), c2pa_cbor::Value::Bytes(vec![0; 32]));
        key_map.insert(cbor_int(-3), c2pa_cbor::Value::Bytes(vec![0; 32]));

        SessionKeys {
            keys: vec![SessionKey {
                key: c2pa_cbor::Value::Map(key_map),
                min_sequence_number: 0,
                created_at: DateT(chrono::Utc::now().to_rfc3339()),
                validity_period: 3600,
                signer_binding: c2pa_cbor::Value::Bytes(binding_bytes),
            }],
        }
    }

    #[test]
    fn signer_binding_valid_passes() {
        let signer = crate::utils::ephemeral_signer::EphemeralSigner::new(
            "test-binding.local",
        )
        .unwrap();
        let ee_cert_der = signer.cert_chain_der[0].clone();
        let binding = make_signer_binding_cose(&signer);
        let keys = session_key_with_binding(binding);

        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();
        validator
            .validate_session_keys(&keys, Some(&ee_cert_der), &mut tracker)
            .unwrap();

        assert!(!tracker.logged_items().iter().any(|i| {
            i.validation_status
                .as_deref()
                .map(|s| s.starts_with("livevideo"))
                .unwrap_or(false)
        }));
    }

    #[test]
    fn signer_binding_bad_signature_fails() {
        let signer = crate::utils::ephemeral_signer::EphemeralSigner::new(
            "test-binding.local",
        )
        .unwrap();
        let ee_cert_der = signer.cert_chain_der[0].clone();

        let other_signer = crate::utils::ephemeral_signer::EphemeralSigner::new(
            "other.local",
        )
        .unwrap();
        let binding = make_signer_binding_cose(&other_signer);
        let keys = session_key_with_binding(binding);

        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();
        let _ = validator.validate_session_keys(&keys, Some(&ee_cert_der), &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
    }

    #[test]
    fn signer_binding_none_cert_skips_verification() {
        let keys = session_key_with_binding(vec![0xDE, 0xAD]);

        let mut validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();
        validator
            .validate_session_keys(&keys, None, &mut tracker)
            .unwrap();

        assert!(!tracker.logged_items().iter().any(|i| {
            i.validation_status
                .as_deref()
                .map(|s| s.starts_with("livevideo"))
                .unwrap_or(false)
        }));
    }
}
