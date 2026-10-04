use std::{fmt, str::FromStr};

use rand::random;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use sha1::{Digest, Sha1};
use uuid::Uuid;

/// A Things 3 entity identifier.
///
/// Internally stored as canonical 16 bytes. Compact base58 IDs decode to
/// those bytes directly; any legacy ID (hyphenated UUIDs, `ACTIONGROUP-<UUID>`,
/// built-in `CC-Things-Tag-*` tags, dated recurring instances, ...) maps to
/// the first 16 bytes of the SHA1 digest of its exact string, which is how
/// Things itself references legacy objects after migrating to compact IDs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct ThingsId([u8; 16]);

impl ThingsId {
    pub fn random() -> Self {
        ThingsId(random())
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn starts_with(&self, prefix: &str) -> bool {
        self.to_string().starts_with(prefix)
    }

    /// Parses an ID as found in sync data, where any non-empty string is a
    /// valid object key. Strings that are not compact IDs are legacy IDs and
    /// are canonicalized through [`legacy_id_to_bytes`].
    pub fn from_wire(s: &str) -> Result<Self, ParseThingsIdError> {
        if s.is_empty() {
            return Err(ParseThingsIdError(s.to_owned()));
        }
        Ok(compact_from_str(s).unwrap_or_else(|| ThingsId(legacy_id_to_bytes(s))))
    }
}

impl fmt::Display for ThingsId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (buf, len) = base58_encode_fixed(&self.0);
        let encoded = std::str::from_utf8(&buf[..len]).expect("base58 output must be ASCII");
        f.write_str(encoded)
    }
}

impl AsRef<[u8; 16]> for ThingsId {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<ThingsId> for String {
    fn from(id: ThingsId) -> Self {
        id.to_string()
    }
}

impl From<&ThingsId> for String {
    fn from(id: &ThingsId) -> Self {
        id.to_string()
    }
}

impl TryFrom<String> for ThingsId {
    type Error = ParseThingsIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse::<ThingsId>()
    }
}

impl TryFrom<&str> for ThingsId {
    type Error = ParseThingsIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse::<ThingsId>()
    }
}

impl FromStr for ThingsId {
    type Err = ParseThingsIdError;

    /// Strict parsing for user input: accepts compact base58 IDs and
    /// hyphenated UUIDs only. Use [`ThingsId::from_wire`] for sync data.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if Uuid::parse_str(s).is_ok() {
            return Ok(ThingsId(legacy_id_to_bytes(s)));
        }
        compact_from_str(s).ok_or_else(|| ParseThingsIdError(s.to_owned()))
    }
}

fn compact_from_str(s: &str) -> Option<ThingsId> {
    if s.is_empty() || s.len() > 22 {
        return None;
    }
    let decoded = base58_decode(s)?;
    let bytes: [u8; 16] = decoded.try_into().ok()?;
    Some(ThingsId(bytes))
}

impl Serialize for ThingsId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ThingsId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ThingsIdVisitor;

        impl Visitor<'_> for ThingsIdVisitor {
            type Value = ThingsId;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a non-empty Things ID string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<ThingsId, E> {
                ThingsId::from_wire(v).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(ThingsIdVisitor)
    }
}

/// Error returned when a string cannot be parsed as a [`ThingsId`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseThingsIdError(String);

impl fmt::Display for ParseThingsIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid Things ID: {:?}", self.0)
    }
}

impl std::error::Error for ParseThingsIdError {}

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode 16 bytes into base58 ASCII, writing into a stack-allocated
/// `[u8; 22]` buffer. Returns the buffer and the number of valid bytes.
pub(crate) fn base58_encode_fixed(raw: &[u8; 16]) -> ([u8; 22], usize) {
    let mut digits = [0u8; 22];
    let mut len = 0usize;

    for &byte in raw {
        let mut carry = byte as u32;
        for digit in digits[..len].iter_mut() {
            let value = (*digit as u32) * 256 + carry;
            *digit = (value % 58) as u8;
            carry = value / 58;
        }
        while carry > 0 {
            digits[len] = (carry % 58) as u8;
            len += 1;
            carry /= 58;
        }
    }

    let leading_ones = raw.iter().take_while(|&&b| b == 0).count();
    let total = leading_ones + len;
    debug_assert!(
        total <= 22,
        "base58_encode_fixed: output length {total} > 22"
    );

    let mut out = [0u8; 22];
    for b in out[..leading_ones].iter_mut() {
        *b = BASE58_ALPHABET[0];
    }
    for (i, &d) in digits[..len].iter().rev().enumerate() {
        out[leading_ones + i] = BASE58_ALPHABET[d as usize];
    }

    (out, total.max(1))
}

fn base58_digit(byte: u8) -> Option<u8> {
    BASE58_ALPHABET
        .iter()
        .position(|&c| c == byte)
        .map(|i| i as u8)
}

fn base58_decode(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() {
        return Some(Vec::new());
    }

    let bytes = input.as_bytes();
    let mut leading_ones = 0usize;
    for b in bytes {
        if *b == b'1' {
            leading_ones += 1;
        } else {
            break;
        }
    }

    let mut decoded: Vec<u8> = Vec::new();
    for &ch in bytes.iter().skip(leading_ones) {
        let mut carry = base58_digit(ch)? as u32;
        for byte in &mut decoded {
            let value = (*byte as u32 * 58) + carry;
            *byte = (value & 0xff) as u8;
            carry = value >> 8;
        }
        while carry > 0 {
            decoded.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut out = Vec::with_capacity(leading_ones + decoded.len());
    out.extend(std::iter::repeat_n(0u8, leading_ones));
    for byte in decoded.iter().rev() {
        out.push(*byte);
    }
    Some(out)
}

/// Canonicalizes a legacy ID the way Things does: the exact string is
/// hashed as-is, without case folding or prefix stripping.
fn legacy_id_to_bytes(id: &str) -> [u8; 16] {
    let digest = Sha1::digest(id.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    const LEGACY_UUID: &str = "3C6BBD49-8D11-4FFF-8B0E-B8F33FA9C00A";
    const LEGACY_UUID_LOWER: &str = "3c6bbd49-8d11-4fff-8b0e-b8f33fa9c00a";
    const LEGACY_ACTION_GROUP_ID: &str = "ACTIONGROUP-3C6BBD49-8D11-4FFF-8B0E-B8F33FA9C00A";
    fn compact_for_legacy() -> String {
        ThingsId::from_str(LEGACY_UUID).unwrap().to_string()
    }

    #[test]
    fn parse_legacy_uuid_uppercase() {
        let id: ThingsId = LEGACY_UUID.parse().unwrap();
        assert_eq!(id.to_string(), compact_for_legacy());
        assert_eq!(id.to_string().len(), 22);
    }

    #[test]
    fn parse_legacy_uuid_preserves_case() {
        let upper: ThingsId = LEGACY_UUID.parse().unwrap();
        let lower: ThingsId = LEGACY_UUID_LOWER.parse().unwrap();
        assert_ne!(upper, lower, "legacy IDs are hashed exactly as written");
    }

    // Expected values below are compact IDs that Things itself uses to
    // reference these legacy objects after migrating an account.
    #[test]
    fn wire_legacy_builtin_tag_matches_things() {
        let id = ThingsId::from_wire("CC-Things-Tag-Important").unwrap();
        assert_eq!(id.to_string(), "XdDBCjmEXEhjZy9A2wFFKP");
    }

    #[test]
    fn wire_legacy_uuid_matches_things() {
        let id = ThingsId::from_wire("06B6F4C9-A15B-42CF-99A6-0E95E6C30568").unwrap();
        assert_eq!(id.to_string(), "24NUhbTg95SWrRGiRozmii");
    }

    #[test]
    fn wire_legacy_action_group_hashes_full_string() {
        let action_group = ThingsId::from_wire(LEGACY_ACTION_GROUP_ID).unwrap();
        assert_eq!(
            action_group,
            ThingsId(legacy_id_to_bytes(LEGACY_ACTION_GROUP_ID))
        );
        assert_ne!(action_group, LEGACY_UUID.parse().unwrap());
    }

    #[test]
    fn wire_accepts_dated_recurring_instance_ids() {
        let raw = "92B73A64-E993-4C4E-80D4-AE0ACF781612-20190629";
        let id = ThingsId::from_wire(raw).unwrap();
        assert_eq!(id, ThingsId(legacy_id_to_bytes(raw)));
    }

    #[test]
    fn wire_keeps_compact_ids() {
        let compact = compact_for_legacy();
        assert_eq!(
            ThingsId::from_wire(&compact).unwrap(),
            compact.parse().unwrap()
        );
    }

    #[test]
    fn wire_rejects_empty_string() {
        assert!(ThingsId::from_wire("").is_err());
    }

    #[test]
    fn strict_parse_rejects_non_uuid_legacy_ids() {
        assert!("CC-Things-Tag-Important".parse::<ThingsId>().is_err());
        assert!(LEGACY_ACTION_GROUP_ID.parse::<ThingsId>().is_err());
    }

    #[test]
    fn serde_deserialize_legacy_action_group_id() {
        let parsed: ThingsId = serde_json::from_str(&format!(r#""{LEGACY_ACTION_GROUP_ID}""#))
            .expect("deserialize legacy action-group ID");
        assert_eq!(parsed, ThingsId::from_wire(LEGACY_ACTION_GROUP_ID).unwrap());
    }

    #[test]
    fn parse_compact_preserved() {
        let compact = compact_for_legacy();
        let id: ThingsId = compact.parse().unwrap();
        assert_eq!(id.to_string(), compact);
    }

    #[test]
    fn empty_string_is_error() {
        let err = "".parse::<ThingsId>();
        assert!(err.is_err());
    }

    #[test]
    fn display_roundtrip() {
        let id: ThingsId = LEGACY_UUID.parse().unwrap();
        let displayed = id.to_string();
        let reparsed: ThingsId = displayed.parse().unwrap();
        assert_eq!(id, reparsed);
    }

    #[test]
    fn random_is_unique() {
        let ids: HashSet<String> = (0..20).map(|_| ThingsId::random().to_string()).collect();
        assert_eq!(ids.len(), 20, "random IDs should be unique");
    }

    #[test]
    fn random_is_compact_length() {
        let id = ThingsId::random();
        let len = id.to_string().len();
        assert!((1..=22).contains(&len), "compact ID length must be 1..=22");
    }

    #[test]
    fn serde_roundtrip_compact() {
        let id: ThingsId = LEGACY_UUID.parse().unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let back: ThingsId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn serde_deserialize_from_legacy_uuid() {
        let json = format!("\"{}\"", LEGACY_UUID);
        let id: ThingsId = serde_json::from_str(&json).unwrap();
        assert_eq!(id.to_string().len(), 22);
        assert_eq!(id.to_string(), compact_for_legacy());
    }

    #[test]
    fn into_string() {
        let id: ThingsId = LEGACY_UUID.parse().unwrap();
        let s: String = id.clone().into();
        assert_eq!(s, id.to_string());
    }

    #[test]
    fn as_ref_bytes() {
        let id: ThingsId = LEGACY_UUID.parse().unwrap();
        let r: &[u8; 16] = id.as_ref();
        assert_eq!(r, id.as_bytes());
    }

    #[test]
    fn rejects_invalid_compact_id() {
        assert!("not-a-things-id".parse::<ThingsId>().is_err());
        assert!("0OIl".parse::<ThingsId>().is_err());
        assert!(
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
                .parse::<ThingsId>()
                .is_err()
        );
    }

    #[test]
    fn base58_roundtrip_for_internal_bytes() {
        let samples = [[0u8; 16], [255u8; 16], legacy_id_to_bytes(LEGACY_UUID)];
        for sample in samples {
            let (buf, len) = base58_encode_fixed(&sample);
            let encoded = std::str::from_utf8(&buf[..len]).unwrap().to_owned();
            let decoded = base58_decode(&encoded).unwrap();
            assert_eq!(decoded, sample);
        }
    }

    #[test]
    fn base58_encode_fixed_matches_display_encoding() {
        let mut samples: Vec<ThingsId> = vec![
            ThingsId([0u8; 16]),
            ThingsId([255u8; 16]),
            LEGACY_UUID.parse().unwrap(),
        ];
        for _ in 0..20 {
            samples.push(ThingsId::random());
        }

        for id in &samples {
            let (buf, len) = base58_encode_fixed(id.as_bytes());
            let fixed = std::str::from_utf8(&buf[..len]).unwrap().to_owned();
            let expected = id.to_string();
            assert_eq!(fixed, expected, "mismatch for {:?}", id.as_bytes());
        }
    }

    #[test]
    fn base58_encode_fixed_preserves_sort_order() {
        let ids: Vec<ThingsId> = (0..50).map(|_| ThingsId::random()).collect();
        let mut by_fixed: Vec<String> = ids
            .iter()
            .map(|id| {
                let (buf, len) = base58_encode_fixed(id.as_bytes());
                std::str::from_utf8(&buf[..len]).unwrap().to_owned()
            })
            .collect();
        by_fixed.sort();

        let mut by_string: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        by_string.sort();

        assert_eq!(
            by_fixed, by_string,
            "base58_encode_fixed sort order != to_string sort order"
        );
    }
}
