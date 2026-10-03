// Module: slate_ntfs_tools::recovery_io::models::metadata::quota_sid_tests
// Purpose: Exercise metadata recovery contracts with independent regression fixtures.
// Created: 2026-10-02
// Architecture: Extracted unchanged from the owner's inline tests; recovery.rs
// includes this file in the original private scope so production internals stay private.

use super::*;

#[test]
fn quota_sid_framing_preserves_identity_and_padding_boundaries() {
    for count in 0..=MAX_SID_SUBAUTHORITIES {
        let length = SID_HEADER_BYTES + usize::from(count) * SID_SUBAUTHORITY_BYTES;
        let mut value = vec![0; length];
        value[0] = QUOTA_SID_REVISION;
        value[1] = count;
        for padded in [false, true] {
            let parsed = quota_sid_bytes(&value, padded).unwrap();
            assert_eq!(parsed, value);
            assert_eq!(parsed.as_ptr(), value.as_ptr());
        }
        for truncated in 0..length {
            let expected = if truncated < SID_HEADER_BYTES { QuotaSidError::Identity } else { QuotaSidError::Framing };
            assert_eq!(quota_sid_bytes(&value[..truncated], true), Err(expected));
        }
        for padding in 1..=MAX_QUOTA_SID_PADDING {
            value.resize(length + padding, 0);
            assert_eq!(quota_sid_bytes(&value, true), Ok(&value[..length]));
            assert_eq!(quota_sid_bytes(&value, false), Err(QuotaSidError::Framing));
        }
        value.resize(length + MAX_QUOTA_SID_PADDING + 1, 0);
        assert_eq!(quota_sid_bytes(&value, true), Err(QuotaSidError::Framing));
        assert_eq!(quota_sid(&value, true).unwrap_err().to_string(), "invalid quota SID length or padding");
        value.truncate(length + 1);
        value[length] = QUOTA_SID_REVISION;
        assert_eq!(quota_sid_bytes(&value, true), Err(QuotaSidError::Framing));
        value.truncate(length);
        value[0] = 0;
        assert_eq!(quota_sid_bytes(&value, false), Err(QuotaSidError::Identity));
        assert_eq!(quota_sid(&value, false).unwrap_err().to_string(), "invalid quota SID");
        value[0] = QUOTA_SID_REVISION;
        value[1] = MAX_SID_SUBAUTHORITIES + 1;
        assert_eq!(quota_sid_bytes(&value, false), Err(QuotaSidError::Identity));
    }
}
