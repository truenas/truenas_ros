//! IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`) from a unix timestamp —
//! the one date shape RFC 9110 §5.6.7 requires servers to *send*. Pure
//! arithmetic (Howard Hinnant's civil-from-days), no clock access: the
//! caller supplies the seconds so serialization stays deterministic and
//! testable.

use std::fmt;

/// A UTC wall-clock instant formatted as an IMF-fixdate via [`fmt::Display`].
///
/// Construct with [`HttpDate::from_unix`]; the glue layer feeds it
/// `SystemTime::now()` once per response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpDate {
    year: i64,
    month: u8,   // 1-12
    day: u8,     // 1-31
    weekday: u8, // 0 = Sunday
    hour: u8,
    minute: u8,
    second: u8,
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
    "Nov", "Dec",
];
const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

impl HttpDate {
    /// Convert seconds since the unix epoch (UTC) into calendar fields.
    ///
    /// Negative inputs (pre-1970) are handled by the same arithmetic; leap
    /// seconds don't exist in unix time, so none are represented.
    pub fn from_unix(secs: i64) -> Self {
        let days = secs.div_euclid(86_400);
        let secs_of_day = secs.rem_euclid(86_400);

        // Civil-from-days (Hinnant): shift the epoch to 0000-03-01 so leap
        // days land at the end of the cycle year.
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097); // [0, 146096]
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11], March-based
        let day = (doy - (153 * mp + 2) / 5 + 1) as u8; // [1, 31]
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8; // [1, 12]
        let year = if month <= 2 { y + 1 } else { y };

        // 1970-01-01 was a Thursday (weekday 4 with Sunday = 0).
        let weekday = (days + 4).rem_euclid(7) as u8;

        Self {
            year,
            month,
            day,
            weekday,
            hour: (secs_of_day / 3_600) as u8,
            minute: (secs_of_day / 60 % 60) as u8,
            second: (secs_of_day % 60) as u8,
        }
    }
}

impl fmt::Display for HttpDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
            WEEKDAYS[usize::from(self.weekday)],
            self.day,
            MONTHS[usize::from(self.month - 1)],
            self.year,
            self.hour,
            self.minute,
            self.second,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_reference_date() {
        // The RFC 9110 example: Sun, 06 Nov 1994 08:49:37 GMT.
        assert_eq!(
            HttpDate::from_unix(784_111_777).to_string(),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
    }

    #[test]
    fn epoch() {
        assert_eq!(
            HttpDate::from_unix(0).to_string(),
            "Thu, 01 Jan 1970 00:00:00 GMT"
        );
    }

    #[test]
    fn leap_day() {
        // 2024-02-29 12:00:00 UTC was a Thursday.
        assert_eq!(
            HttpDate::from_unix(1_709_208_000).to_string(),
            "Thu, 29 Feb 2024 12:00:00 GMT"
        );
    }

    #[test]
    fn century_non_leap() {
        // 1900 was not a leap year: the day after 1900-02-28 is March 1.
        // -2203891200 = 1900-03-01 00:00:00 UTC (a Thursday).
        assert_eq!(
            HttpDate::from_unix(-2_203_891_200).to_string(),
            "Thu, 01 Mar 1900 00:00:00 GMT"
        );
    }

    #[test]
    fn far_future() {
        // 2100 is also not a leap year. 4107542399 = 2100-02-28 23:59:59 UTC.
        assert_eq!(
            HttpDate::from_unix(4_107_542_399).to_string(),
            "Sun, 28 Feb 2100 23:59:59 GMT"
        );
    }
}
