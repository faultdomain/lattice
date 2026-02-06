//! Formatting utilities for table output and age display

use chrono::{DateTime, Utc};

/// Format a timestamp as a human-readable age (e.g., "2d", "5h", "30m", "15s")
pub fn format_age(timestamp: &DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(*timestamp);

    let total_secs = duration.num_seconds();
    if total_secs < 0 {
        return "0s".to_string();
    }

    let days = duration.num_days();
    if days > 0 {
        return format!("{}d", days);
    }

    let hours = duration.num_hours();
    if hours > 0 {
        return format!("{}h", hours);
    }

    let minutes = duration.num_minutes();
    if minutes > 0 {
        return format!("{}m", minutes);
    }

    format!("{}s", total_secs)
}

/// Print rows as a column-aligned table with headers.
///
/// Each row is a Vec of strings. The first row is treated as headers.
pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    if rows.is_empty() {
        // Print headers only
        println!("{}", headers.join("  "));
        return;
    }

    // Calculate column widths
    let num_cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < num_cols {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }

    // Print header
    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:<width$}", h, width = widths[i]))
        .collect();
    println!("{}", header_line.join("  "));

    // Print rows
    for row in rows {
        let line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let w = widths.get(i).copied().unwrap_or(0);
                format!("{:<width$}", cell, width = w)
            })
            .collect();
        println!("{}", line.join("  "));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_format_age_seconds() {
        let ts = Utc::now() - Duration::seconds(45);
        assert_eq!(format_age(&ts), "45s");
    }

    #[test]
    fn test_format_age_minutes() {
        let ts = Utc::now() - Duration::minutes(12);
        assert_eq!(format_age(&ts), "12m");
    }

    #[test]
    fn test_format_age_hours() {
        let ts = Utc::now() - Duration::hours(3);
        assert_eq!(format_age(&ts), "3h");
    }

    #[test]
    fn test_format_age_days() {
        let ts = Utc::now() - Duration::days(7);
        assert_eq!(format_age(&ts), "7d");
    }

    #[test]
    fn test_format_age_future_timestamp() {
        let ts = Utc::now() + Duration::hours(1);
        assert_eq!(format_age(&ts), "0s");
    }

    #[test]
    fn test_format_age_zero() {
        let ts = Utc::now();
        assert_eq!(format_age(&ts), "0s");
    }
}
