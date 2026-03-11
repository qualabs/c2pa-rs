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

use std::collections::HashMap;

use crate::{
    assertions::{ContinuityMethod, LiveVideoSegment},
    status_tracker::StatusTracker,
};

pub(super) fn make_segment(sequence_number: u64, stream_id: &str) -> LiveVideoSegment {
    LiveVideoSegment {
        sequence_number,
        stream_id: stream_id.to_string(),
        continuity_method: ContinuityMethod::ManifestId,
        previous_manifest_id: Some("urn:c2pa:prev-manifest".to_string()),
        additional_fields: HashMap::new(),
    }
}

pub(super) fn make_uuid_box(include_c2pa_uuid: bool) -> Vec<u8> {
    let mut data = Vec::new();
    let size: u32 = 24;
    data.extend_from_slice(&size.to_be_bytes());
    data.extend_from_slice(b"uuid");
    if include_c2pa_uuid {
        data.extend_from_slice(&super::C2PA_UUID);
    } else {
        data.extend_from_slice(&[0u8; 16]);
    }
    data
}

pub(super) fn make_mdat_box() -> Vec<u8> {
    let mut data = Vec::new();
    let size: u32 = 8;
    data.extend_from_slice(&size.to_be_bytes());
    data.extend_from_slice(b"mdat");
    data
}

pub(super) fn make_emsg_box() -> Vec<u8> {
    let mut data = Vec::new();
    let size: u32 = 8;
    data.extend_from_slice(&size.to_be_bytes());
    data.extend_from_slice(b"emsg");
    data
}

pub(super) fn aggregate_tracker() -> StatusTracker {
    StatusTracker::default()
}
