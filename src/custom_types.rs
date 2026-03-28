/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */
use arrayvec::ArrayString;
use hickory_proto::op::response_code::ResponseCode as HickoryResponseCode;
use hickory_proto::rr::record_type::RecordType as HickoryRecordType;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::mem::MaybeUninit;
use std::ptr;

/// A wrapper type around `HickoryRecordType` to implement custom traits and behaviors.
///
/// `ProtoRecordType` encapsulates `hickory_proto` `ResponseCode` to provide additional functionality
/// such as serialization, custom ordering, and display formatting. This allows for easy integration
/// with data processing frameworks, efficient comparisons, and formatted output.
///
/// This type is designed to interoperate seamlessly with the `hickory_proto` `ResponseCode` while
/// enabling compatibility with various Rust traits required for structured data handling.
///
/// # Usage
///
/// `ProtoRecordType` can be used in collections such as `BTreeSet` or `HashSet` that require
/// `Ord` or `Hash` traits. Additionally, it can be serialized/deserialized using Serde for
/// storage or transmission, and formatted using the `fmt::Display` trait for logging or reporting.
///
/// # Implementation Notes
///
/// - The `Ord` and `PartialOrd` traits rely on the internal numeric value of `HickoryRecordType`
///   for comparisons.
/// - `Serialize` and `Deserialize` convert the wrapped type to and from a string representation.
///
/// # Examples
///
/// ```rust
/// let record_type: ProtoRecordType = HickoryRecordType::A.into();
/// println!("Record Type: {}", record_type); // Outputs the string representation.
/// ```
///
/// # Type Safety
///
/// The use of `From` and `Into` traits ensures safe conversions between `ProtoRecordType`
/// and its underlying `HickoryRecordType`, avoiding runtime errors and unexpected behaviors.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtoRecordType(HickoryRecordType);

impl From<HickoryRecordType> for ProtoRecordType {
    fn from(code: HickoryRecordType) -> Self {
        ProtoRecordType(code)
    }
}

impl From<ProtoRecordType> for HickoryRecordType {
    fn from(wrapped: ProtoRecordType) -> Self {
        wrapped.0
    }
}

impl ProtoRecordType {
    pub fn as_str(&self) -> &'static str {
        Into::<&str>::into(self.0)
    }
}

impl Ord for ProtoRecordType {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_value: u16 = self.0.into();
        let other_value: u16 = other.0.into();
        self_value.cmp(&other_value)
    }
}

impl PartialOrd for ProtoRecordType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for ProtoRecordType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(Into::<&str>::into(self.0))
    }
}

impl<'de> Deserialize<'de> for ProtoRecordType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let record_type = value
            .parse::<HickoryRecordType>()
            .map_err(serde::de::Error::custom)?;
        Ok(ProtoRecordType(record_type))
    }
}

impl fmt::Display for ProtoRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A wrapper type around `HickoryResponseCode` to implement custom traits and behaviors.
///
/// `ProtoResponseCode` is designed to provide additional functionality for response codes,
/// such as serialization, custom ordering, and display formatting. It allows the response
/// code to be treated as a structured data type, making it easier to handle in different
/// contexts such as data storage, comparisons, and user-facing outputs.
///
/// This type serves as an intermediary between the `hickory_proto` `ResponseCode` and external systems
/// that require the response code to implement traits like `Ord`, `Serialize`, or `fmt::Display`.
///
/// # Usage
///
/// `ProtoResponseCode` can be used to store and compare DNS response codes in collections
/// that require `Ord` or `Hash` traits. It can also be serialized/deserialized using Serde for
/// compatibility with data storage formats such as JSON or CSV.
///
/// # Implementation Details
///
/// - The `Ord` and `PartialOrd` traits use the internal numeric value of `hickory_proto` `ResponseCode`
///   for ordering, ensuring consistent comparisons.
/// - The `Serialize` and `Deserialize` traits convert the wrapped type into its string representation
///   for human-readable output and structured data handling.
///
/// # Examples
///
/// ```rust
/// let response_code: ProtoResponseCode = HickoryResponseCode::NoError.into();
/// println!("Response Code: {}", response_code); // Outputs a string representation such as "NoError".
/// ```
///
/// # Design Considerations
///
/// Using `ProtoResponseCode` provides a consistent way to interact with response codes
/// across the application, encapsulating the complexity of the internal representation
/// and providing a clean interface for external use.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtoResponseCode(HickoryResponseCode);

#[derive(Deserialize)]
#[serde(untagged)]
enum ProtoResponseCodeRepr {
    Numeric(u16),
    Text(String),
}

impl From<HickoryResponseCode> for ProtoResponseCode {
    fn from(code: HickoryResponseCode) -> Self {
        ProtoResponseCode(code)
    }
}

impl From<ProtoResponseCode> for HickoryResponseCode {
    fn from(wrapped: ProtoResponseCode) -> Self {
        wrapped.0
    }
}

impl ProtoResponseCode {
    pub fn as_str(&self) -> &'static str {
        self.0.to_str()
    }
}

impl Ord for ProtoResponseCode {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_value: u16 = self.0.into();
        let other_value: u16 = other.0.into();
        self_value.cmp(&other_value)
    }
}

impl PartialOrd for ProtoResponseCode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for ProtoResponseCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.to_str())
    }
}

impl<'de> Deserialize<'de> for ProtoResponseCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let code = ProtoResponseCodeRepr::deserialize(deserializer)?;

        match code {
            ProtoResponseCodeRepr::Numeric(code) => Ok(ProtoResponseCode(code.into())),
            ProtoResponseCodeRepr::Text(text) => parse_response_code_text(&text)
                .map(ProtoResponseCode)
                .ok_or_else(|| {
                    serde::de::Error::custom(format!("unsupported response code '{text}'"))
                }),
        }
    }
}

impl fmt::Display for ProtoResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

fn parse_response_code_text(value: &str) -> Option<HickoryResponseCode> {
    let normalized = value
        .chars()
        .filter(|character| !matches!(character, ' ' | '-' | '_'))
        .flat_map(char::to_lowercase)
        .collect::<String>();

    match normalized.as_str() {
        "noerror" => Some(HickoryResponseCode::NoError),
        "formerror" | "formerr" => Some(HickoryResponseCode::FormErr),
        "serverfailure" | "servfail" => Some(HickoryResponseCode::ServFail),
        "nonexistentdomain" | "nxdomain" => Some(HickoryResponseCode::NXDomain),
        "notimplemented" | "notimp" => Some(HickoryResponseCode::NotImp),
        "queryrefused" | "refused" => Some(HickoryResponseCode::Refused),
        "nameshouldnotexist" | "yxdomain" => Some(HickoryResponseCode::YXDomain),
        "rrsetshouldnotexist" | "yxrrset" => Some(HickoryResponseCode::YXRRSet),
        "rrsetdoesnotexist" | "nxrrset" => Some(HickoryResponseCode::NXRRSet),
        "notauthorized" | "notauth" => Some(HickoryResponseCode::NotAuth),
        "namenotinzone" | "notzone" => Some(HickoryResponseCode::NotZone),
        "badoptionversions" | "badvers" | "badsig" | "tsigfailure" => {
            Some(HickoryResponseCode::BADVERS)
        }
        "keynotrecognized" | "badkey" => Some(HickoryResponseCode::BADKEY),
        "signatureoutoftimewindow" | "badtime" => Some(HickoryResponseCode::BADTIME),
        "badtkeymode" | "badmode" => Some(HickoryResponseCode::BADMODE),
        "duplicatekeyname" | "badname" => Some(HickoryResponseCode::BADNAME),
        "algorithmnotsupported" | "badalg" => Some(HickoryResponseCode::BADALG),
        "badtruncation" | "badtrunc" => Some(HickoryResponseCode::BADTRUNC),
        "badservercookie" | "badcookie" => Some(HickoryResponseCode::BADCOOKIE),
        _ => normalized
            .parse::<u16>()
            .ok()
            .map(Into::<HickoryResponseCode>::into),
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsName255 {
    bytes: [MaybeUninit<u8>; 255],
    len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsNameTooLong;

impl fmt::Display for DnsNameTooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DNS name exceeds 255-byte capacity")
    }
}

impl std::error::Error for DnsNameTooLong {}

impl DnsName255 {
    pub fn new(value: &str) -> Result<Self, DnsNameTooLong> {
        let mut name = Self::default();
        name.try_push_str(value)?;
        Ok(name)
    }

    pub fn as_str(&self) -> &str {
        // SAFETY: instances are constructed only from valid UTF-8 `&str` or `char` inputs.
        unsafe { std::str::from_utf8_unchecked(self.as_bytes()) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: only the prefix `0..len` is ever exposed, and every mutating constructor writes
        // that prefix before advancing `len`.
        unsafe {
            std::slice::from_raw_parts(self.bytes.as_ptr().cast::<u8>(), usize::from(self.len))
        }
    }

    pub fn try_push(&mut self, ch: char) -> Result<(), DnsNameTooLong> {
        let mut buffer = [0_u8; 4];
        self.try_push_str(ch.encode_utf8(&mut buffer))
    }

    pub fn try_push_str(&mut self, value: &str) -> Result<(), DnsNameTooLong> {
        let start = usize::from(self.len);
        let end = start
            .checked_add(value.len())
            .filter(|end| *end <= self.bytes.len())
            .ok_or(DnsNameTooLong)?;

        // SAFETY: bounds were checked above and source/destination do not overlap.
        unsafe {
            ptr::copy_nonoverlapping(
                value.as_ptr(),
                self.bytes.as_mut_ptr().cast::<u8>().add(start),
                value.len(),
            );
        }
        self.len = end as u8;
        Ok(())
    }
}

impl Default for DnsName255 {
    fn default() -> Self {
        Self {
            bytes: [MaybeUninit::uninit(); 255],
            len: 0,
        }
    }
}

impl PartialEq for DnsName255 {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for DnsName255 {}

impl PartialOrd for DnsName255 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DnsName255 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl Hash for DnsName255 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl fmt::Debug for DnsName255 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DnsName255").field(&self.as_str()).finish()
    }
}

impl fmt::Display for DnsName255 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for DnsName255 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DnsName255 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        DnsName255::new(&value).map_err(serde::de::Error::custom)
    }
}

/// A fixed-size string wrapper around `ArrayString` to enable serialization and deserialization.
///
/// `FixedSizeString` ensures that strings do not exceed a specified length at compile time.
/// This is particularly useful for optimizing memory usage and ensuring data consistency
/// when dealing with fixed-size records or interfacing with systems that require fixed-length strings.
///
/// # Type Parameters
///
/// * `N` - The maximum capacity of the string, defined at compile time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedSizeString<const N: usize>(ArrayString<N>);

impl<const N: usize> FixedSizeString<N> {
    /// Creates a new, empty `FixedSizeString`.
    ///
    /// Initializes an empty `ArrayString` with a capacity of `N` characters.
    ///
    /// # Returns
    ///
    /// A new instance of `FixedSizeString` containing an empty string.
    ///
    /// # Example
    ///
    /// ```rust
    /// let empty_string: FixedSizeString<10> = FixedSizeString::new_empty();
    /// assert_eq!(empty_string.as_str(), "");
    /// ```
    #[allow(dead_code)]
    pub fn new_empty() -> Self {
        FixedSizeString(ArrayString::new())
    }

    /// Creates a new `FixedSizeString` from a given string slice.
    ///
    /// Attempts to create an `ArrayString` from the provided string slice. If the string
    /// exceeds the predefined capacity `N`, it defaults to an empty string to prevent
    /// buffer overflows.
    ///
    /// # Parameters
    ///
    /// - `value`: A string slice that holds the initial value of the string.
    ///
    /// # Returns
    ///
    /// A `FixedSizeString` instance containing the provided string if it fits within the capacity.
    /// Otherwise, it returns a capacity error and leaves the fallback behavior to the caller.
    ///
    /// # Example
    ///
    /// ```rust
    /// let fixed_string: FixedSizeString<10> = FixedSizeString::new("Hello").unwrap();
    /// assert_eq!(fixed_string.as_str(), "Hello");
    /// ```
    #[allow(dead_code)]
    pub fn new(value: &str) -> Result<Self, arrayvec::CapacityError<&str>> {
        ArrayString::from(value).map(Into::into)
    }

    #[allow(dead_code)]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<const N: usize> fmt::Display for FixedSizeString<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.as_str())
    }
}

impl<const N: usize> Serialize for FixedSizeString<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str()) // Serialize the inner string slice.
    }
}

impl<const N: usize> From<ArrayString<N>> for FixedSizeString<N> {
    fn from(array_string: ArrayString<N>) -> Self {
        FixedSizeString(array_string)
    }
}

impl From<DnsName255> for FixedSizeString<255> {
    fn from(name: DnsName255) -> Self {
        FixedSizeString::new(name.as_str())
            .expect("DnsName255 always fits into FixedSizeString<255>")
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedSizeString<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ArrayString::from(&s)
            .map(FixedSizeString)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::{DnsName255, FixedSizeString, HickoryResponseCode, ProtoResponseCode};
    use std::mem::size_of;

    #[test]
    fn proto_response_code_deserializes_extended_numeric_codes() {
        let code: ProtoResponseCode =
            serde_json::from_str("4095").expect("numeric response code parses");
        let parsed: HickoryResponseCode = code.into();

        assert_eq!(u16::from(parsed), 4095);
    }

    #[test]
    fn proto_response_code_round_trips_string_representation() {
        let serialized =
            serde_json::to_string(&ProtoResponseCode::from(HickoryResponseCode::ServFail))
                .expect("response code serializes");
        let parsed: ProtoResponseCode =
            serde_json::from_str(&serialized).expect("serialized response code parses");
        let parsed: HickoryResponseCode = parsed.into();

        assert_eq!(parsed, HickoryResponseCode::ServFail);
    }

    #[test]
    fn fixed_size_string_new_returns_error_when_capacity_is_exceeded() {
        let error = FixedSizeString::<4>::new("hello").expect_err("overflow must fail");

        assert_eq!(error.element(), "hello");
    }

    #[test]
    fn dns_name_255_rejects_values_longer_than_capacity() {
        let oversized = "a".repeat(256);

        let error = DnsName255::new(&oversized).expect_err("overflow must fail");

        assert_eq!(error, super::DnsNameTooLong);
    }

    #[test]
    fn dns_name_255_uses_string_order_and_not_padding_order() {
        let short = DnsName255::new("a").expect("name fits");
        let long = DnsName255::new("aa").expect("name fits");

        assert!(short < long);
    }

    #[test]
    fn dns_name_255_stays_within_256_byte_layout_budget() {
        assert_eq!(size_of::<DnsName255>(), 256);
    }

    #[test]
    fn dns_name_255_round_trips_through_serde_as_a_string() {
        let serialized = serde_json::to_string(&DnsName255::new("example.com").expect("name fits"))
            .expect("dns name serializes");
        let parsed: DnsName255 = serde_json::from_str(&serialized).expect("dns name parses");

        assert_eq!(serialized, "\"example.com\"");
        assert_eq!(parsed.as_str(), "example.com");
    }
}
