use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) struct HttpDate(SystemTime);

impl HttpDate {
    pub(crate) fn now() -> Self {
        Self(std::time::SystemTime::now())
    }
}

impl fmt::Display for HttpDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let duration = self.0.duration_since(UNIX_EPOCH).map_err(|_| fmt::Error)?;

        let secs = duration.as_secs();
        let days = (secs / 86_400) as i64;
        let secs_of_day = secs % 86_400;

        let weekday = WEEKDAYS[((days + 4).rem_euclid(7)) as usize];
        let (year, month, day) = civil_from_days(days);

        let hour = secs_of_day / 3_600;
        let minute = (secs_of_day / 60) % 60;
        let second = secs_of_day % 60;

        write!(
            f,
            "{weekday}, {day:02} {month} {year:04} {hour:02}:{minute:02}:{second:02} GMT",
            month = MONTHS[(month - 1) as usize],
        )
    }
}

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

// Days since 1970-01-01 UTC -> Gregorian year/month/day.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;

    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };

    (year, month as u32, day as u32)
}
