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

//! Defines the `c2pa.session-keys` assertion ([§18.25]) for live video streams.
//!
//! [§18.25]: https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_session_keys

use serde::{Deserialize, Serialize};

use super::labels;
use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    cbor_types::DateT,
    Result,
};

/// A single session key used to verify VSI signatures ([§18.25]).
///
/// [§18.25]: https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_session_keys
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SessionKey {
    /// COSE_Key (RFC 9052) with mandatory `kid`, stored as raw CBOR.
    pub key: c2pa_cbor::Value,
    pub min_sequence_number: u64,
    /// Key creation time (CBOR tag 0 date-time string).
    pub created_at: DateT,
    /// Seconds from `created_at` for which this key is valid.
    pub validity_period: u64,
    /// COSE_Sign1_Tagged binding this key to the signer's certificate, stored as raw CBOR.
    pub signer_binding: c2pa_cbor::Value,
}

/// The `c2pa.session-keys` assertion embedded in a live video init segment manifest ([§18.25]).
///
/// [§18.25]: https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_session_keys
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SessionKeys {
    pub keys: Vec<SessionKey>,
}

impl SessionKeys {
    pub const LABEL: &'static str = labels::SESSION_KEYS;
}

impl AssertionBase for SessionKeys {
    const LABEL: &'static str = Self::LABEL;

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

impl AssertionCbor for SessionKeys {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::assertions::labels;

    fn minimal_session_key() -> SessionKey {
        // Minimal COSE_Key map: {1: 2} — kty: EC2
        let mut key_map = std::collections::BTreeMap::new();
        key_map.insert(
            c2pa_cbor::Value::Integer(1.into()),
            c2pa_cbor::Value::Integer(2.into()),
        );
        SessionKey {
            key: c2pa_cbor::Value::Map(key_map),
            min_sequence_number: 0,
            created_at: DateT("2026-01-01T00:00:00Z".to_string()),
            validity_period: 3600,
            signer_binding: c2pa_cbor::Value::Bytes(vec![]),
        }
    }

    #[test]
    fn label_matches_spec() {
        assert_eq!(SessionKeys::LABEL, labels::SESSION_KEYS);
        assert_eq!(SessionKeys::LABEL, "c2pa.session-keys");
    }

    #[test]
    fn round_trip_cbor_single_key() {
        let original = SessionKeys {
            keys: vec![minimal_session_key()],
        };
        let assertion = original.to_assertion().unwrap();
        let restored = SessionKeys::from_assertion(&assertion).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn round_trip_cbor_multiple_keys() {
        let original = SessionKeys {
            keys: vec![minimal_session_key(), minimal_session_key()],
        };
        let assertion = original.to_assertion().unwrap();
        let restored = SessionKeys::from_assertion(&assertion).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn round_trip_preserves_validity_period() {
        let key = SessionKey {
            validity_period: 86400,
            ..minimal_session_key()
        };
        let original = SessionKeys { keys: vec![key] };
        let assertion = original.to_assertion().unwrap();
        let restored = SessionKeys::from_assertion(&assertion).unwrap();
        assert_eq!(restored.keys[0].validity_period, 86400);
    }
}
