//! UTC timestamp conversion and JSON serialization.

use serde::{Deserialize, Deserializer, Serializer, de, ser};
use time::{OffsetDateTime, PrimitiveDateTime, UtcOffset, format_description::well_known::Rfc3339};

/// Returns the current UTC time in the database timestamp type.
#[must_use]
pub fn now_utc() -> PrimitiveDateTime {
    utc_datetime(OffsetDateTime::now_utc())
}

/// Converts an offset timestamp to a UTC database timestamp.
#[must_use]
pub fn utc_datetime(value: OffsetDateTime) -> PrimitiveDateTime {
    let utc = value.to_offset(UtcOffset::UTC);
    PrimitiveDateTime::new(utc.date(), utc.time())
}

/// Parses an RFC 3339 timestamp or a legacy UTC timestamp with no offset.
///
/// # Errors
///
/// Returns a parse error if the timestamp is invalid.
pub fn parse(value: &str) -> Result<PrimitiveDateTime, time::error::Parse> {
    let legacy = time::macros::format_description!(
        "[year]-[month]-[day][first [T][ ]][hour]:[minute]:[second][optional [.[subsecond]]]"
    );
    parse_rfc3339(value).or_else(|_| PrimitiveDateTime::parse(value, legacy))
}

/// Parses an offset-bearing timestamp and converts it to UTC.
pub(crate) fn parse_rfc3339(value: &str) -> Result<PrimitiveDateTime, time::error::Parse> {
    if !matches!(value.as_bytes().get(10), Some(b'T' | b't' | b' ')) {
        return Err(time::error::ParseFromDescription::InvalidComponent("separator").into());
    }
    let timestamp = OffsetDateTime::parse(value, &Rfc3339)?;
    // Rebuilding from the epoch checks the range after applying the offset.
    OffsetDateTime::from_unix_timestamp_nanos(timestamp.unix_timestamp_nanos())
        .map(utc_datetime)
        .map_err(|error| time::error::TryFromParsed::from(error).into())
}

/// Serializes a database timestamp as an RFC 3339 UTC string.
///
/// # Errors
///
/// Returns an error if the timestamp cannot be represented or the serializer fails.
pub fn serialize<S: Serializer>(
    value: &PrimitiveDateTime,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let value = value
        .assume_utc()
        .format(&Rfc3339)
        .map_err(ser::Error::custom)?;
    serializer.serialize_str(&value)
}

/// Deserializes an RFC 3339 or legacy UTC string.
///
/// # Errors
///
/// Returns an error if the input is not a valid timestamp string.
pub fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<PrimitiveDateTime, D::Error> {
    parse(&String::deserialize(deserializer)?).map_err(de::Error::custom)
}

#[derive(serde::Serialize, Deserialize)]
struct Timestamp(#[serde(with = "self")] PrimitiveDateTime);

/// Serde adapter for nullable timestamps.
pub mod option {
    use super::{Deserialize, Deserializer, PrimitiveDateTime, Serializer, Timestamp};
    use serde::Serialize;

    /// Serializes an optional timestamp as a UTC string or null.
    ///
    /// # Errors
    ///
    /// Returns an error if formatting or serialization fails.
    pub fn serialize<S: Serializer>(
        value: &Option<PrimitiveDateTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.map(Timestamp).serialize(serializer)
    }

    /// Deserializes a UTC string or null.
    ///
    /// # Errors
    ///
    /// Returns an error if the input cannot be parsed.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<PrimitiveDateTime>, D::Error> {
        Ok(Option::<Timestamp>::deserialize(deserializer)?.map(|timestamp| timestamp.0))
    }
}

/// Serde adapter for named nullable timestamps in intersection responses.
pub(crate) mod map {
    use serde::ser::SerializeMap;
    use std::collections::HashMap;

    use super::{PrimitiveDateTime, Serializer, Timestamp};

    pub fn serialize<S: Serializer>(
        values: &HashMap<String, Option<PrimitiveDateTime>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(values.len()))?;
        for (name, value) in values {
            map.serialize_entry(name, &value.map(Timestamp))?;
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_timestamps_are_utc_strings_and_accept_legacy_inputs() {
        let expected = time::macros::datetime!(2026-11-22 01:02:03.123456789);
        for timestamp in [
            "2026-11-22T01:02:03.123456789Z",
            "2026-11-22T01:02:03.123456789",
            "2026-11-22 01:02:03.123456789",
            "2026-11-22 01:02:03.123456789Z",
            "2026-11-22T02:02:03.123456789+01:00",
        ] {
            let json = serde_json::to_string(timestamp).unwrap();
            assert_eq!(
                serde_json::from_str::<Timestamp>(&json).unwrap().0,
                expected
            );
        }
        assert_eq!(
            serde_json::to_string(&Timestamp(expected)).unwrap(),
            r#""2026-11-22T01:02:03.123456789Z""#
        );
        assert!(serde_json::from_str::<Timestamp>("[2026,326,1,2,3,0]").is_err());
    }

    #[tokio::test]
    async fn sqlite_binds_timestamps_in_the_legacy_index_format() {
        use sea_orm::{ConnectionTrait, Database, sea_query::Query};

        let db = Database::connect("sqlite::memory:").await.unwrap();
        for legacy in [
            "2026-11-22 01:02:03",
            "2026-11-22 01:02:03.100",
            "2026-11-22 01:02:03.123400",
            "2026-11-22 01:02:03.123456700",
        ] {
            let statement = Query::select().expr(parse(legacy).unwrap()).take();
            let row = db.query_one(&statement).await.unwrap().unwrap();
            assert_eq!(row.try_get_by_index::<String>(0).unwrap(), legacy);
        }
    }
}
