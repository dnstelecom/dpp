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

/// Converts `HickoryRecordType` into `ProtoRecordType`.
impl From<HickoryRecordType> for ProtoRecordType {
    fn from(code: HickoryRecordType) -> Self {
        ProtoRecordType(code)
    }
}

/// Converts `ProtoRecordType` back into `HickoryRecordType`.
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

/// Custom ordering for `ProtoRecordType` based on the internal numeric representation.
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

/// Implements `Serialize` trait for `ProtoRecordType`.
impl Serialize for ProtoRecordType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(Into::<&str>::into(self.0))
    }
}

/// Implements `Deserialize` trait for `ProtoRecordType`.
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

/// Implements `fmt::Display` for `ProtoRecordType`.
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

    /// Retrieves the string slice contained within the `FixedSizeString`.
    ///
    /// # Returns
    ///
    /// A string slice representing the contents of the `FixedSizeString`.
    ///
    /// # Example
    ///
    /// ```rust
    /// let fixed_string: FixedSizeString<10> = FixedSizeString::new("Hello").unwrap();
    /// assert_eq!(fixed_string.as_str(), "Hello");
    /// ```
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<const N: usize> fmt::Display for FixedSizeString<N> {
    /// Formats the `FixedSizeString` for display purposes.
    ///
    /// This implementation allows `FixedSizeString` instances to be printed using `{}` in format strings.
    ///
    /// # Parameters
    ///
    /// - `f`: The formatter.
    ///
    /// # Returns
    ///
    /// A `fmt::Result` indicating the success or failure of the formatting operation.
    ///
    /// # Example
    ///
    /// ```rust
    /// let fixed_string: FixedSizeString<10> = FixedSizeString::new("Hello").unwrap();
    /// println!("{}", fixed_string); // Outputs: Hello
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.as_str())
    }
}

impl<const N: usize> Serialize for FixedSizeString<N> {
    /// Serializes the `FixedSizeString` into a string format.
    ///
    /// This implementation allows `FixedSizeString` instances to be serialized using Serde.
    ///
    /// # Parameters
    ///
    /// - `serializer`: The serializer to which the string will be serialized.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the success or failure of the serialization operation.
    ///
    /// # Example
    ///
    /// ```rust
    /// let fixed_string: FixedSizeString<10> = FixedSizeString::new("Hello").unwrap();
    /// let serialized = serde_json::to_string(&fixed_string).unwrap();
    /// assert_eq!(serialized, "\"Hello\"");
    /// ```
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str()) // Serialize the inner string slice.
    }
}

impl<const N: usize> From<ArrayString<N>> for FixedSizeString<N> {
    /// Converts an `ArrayString` into a `FixedSizeString`.
    ///
    /// This implementation allows for seamless conversion from `ArrayString` to `FixedSizeString`.
    ///
    /// # Parameters
    ///
    /// - `array_string`: The `ArrayString` instance to be converted.
    ///
    /// # Returns
    ///
    /// A new `FixedSizeString` containing the contents of the provided `ArrayString`.
    ///
    /// # Example
    ///
    /// ```rust
    /// let array_string: ArrayString<10> = ArrayString::from("Hello").unwrap();
    /// let fixed_string: FixedSizeString<10> = array_string.into();
    /// assert_eq!(fixed_string.as_str(), "Hello");
    /// ```
    fn from(array_string: ArrayString<N>) -> Self {
        FixedSizeString(array_string)
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedSizeString<N> {
    /// Deserializes a string into a `FixedSizeString`.
    ///
    /// This implementation allows `FixedSizeString` instances to be deserialized using Serde.
    /// If the incoming string exceeds the predefined capacity `N`, deserialization will fail.
    ///
    /// # Parameters
    ///
    /// - `deserializer`: The deserializer from which the string will be deserialized.
    ///
    /// # Returns
    ///
    /// A `Result` containing the deserialized `FixedSizeString` or a deserialization error.
    ///
    /// # Example
    ///
    /// ```rust
    /// let json_str = "\"Hello\"";
    /// let fixed_string: FixedSizeString<10> = serde_json::from_str(json_str).unwrap();
    /// assert_eq!(fixed_string.as_str(), "Hello");
    /// ```
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
    use super::{FixedSizeString, HickoryResponseCode, ProtoResponseCode};

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
}
