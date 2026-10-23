use std::cmp::Ordering;

use crate::memory::ProcessMemory;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueType {
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
}

impl ValueType {
    pub const ALL: [Self; 10] = [
        Self::I8,
        Self::U8,
        Self::I16,
        Self::U16,
        Self::I32,
        Self::U32,
        Self::I64,
        Self::U64,
        Self::F32,
        Self::F64,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::I8 => "i8",
            Self::U8 => "u8",
            Self::I16 => "i16",
            Self::U16 => "u16",
            Self::I32 => "i32",
            Self::U32 => "u32",
            Self::I64 => "i64",
            Self::U64 => "u64",
            Self::F32 => "f32",
            Self::F64 => "f64",
        }
    }

    pub const fn size(self) -> usize {
        match self {
            Self::I8 | Self::U8 => 1,
            Self::I16 | Self::U16 => 2,
            Self::I32 | Self::U32 | Self::F32 => 4,
            Self::I64 | Self::U64 | Self::F64 => 8,
        }
    }

    pub fn parse(self, text: &str) -> Result<Vec<u8>, String> {
        macro_rules! parse_number {
            ($type:ty) => {
                text.trim()
                    .parse::<$type>()
                    .map(<$type>::to_le_bytes)
                    .map(Vec::from)
                    .map_err(|error| format!("invalid {} value: {error}", self.label()))
            };
        }

        match self {
            Self::I8 => parse_number!(i8),
            Self::U8 => parse_number!(u8),
            Self::I16 => parse_number!(i16),
            Self::U16 => parse_number!(u16),
            Self::I32 => parse_number!(i32),
            Self::U32 => parse_number!(u32),
            Self::I64 => parse_number!(i64),
            Self::U64 => parse_number!(u64),
            Self::F32 => parse_number!(f32),
            Self::F64 => parse_number!(f64),
        }
    }

    pub fn format(self, bytes: &[u8]) -> String {
        macro_rules! format_number {
            ($type:ty, $length:expr) => {{
                let Ok(array) = <[u8; $length]>::try_from(bytes) else {
                    return "?".into();
                };
                <$type>::from_le_bytes(array).to_string()
            }};
        }

        match self {
            Self::I8 => format_number!(i8, 1),
            Self::U8 => format_number!(u8, 1),
            Self::I16 => format_number!(i16, 2),
            Self::U16 => format_number!(u16, 2),
            Self::I32 => format_number!(i32, 4),
            Self::U32 => format_number!(u32, 4),
            Self::I64 => format_number!(i64, 8),
            Self::U64 => format_number!(u64, 8),
            Self::F32 => format_number!(f32, 4),
            Self::F64 => format_number!(f64, 8),
        }
    }

    fn compare(self, left: &[u8], right: &[u8]) -> Option<Ordering> {
        macro_rules! compare_number {
            ($type:ty, $length:expr) => {{
                let left = <$type>::from_le_bytes(<[u8; $length]>::try_from(left).ok()?);
                let right = <$type>::from_le_bytes(<[u8; $length]>::try_from(right).ok()?);
                left.partial_cmp(&right)
            }};
        }

        match self {
            Self::I8 => compare_number!(i8, 1),
            Self::U8 => compare_number!(u8, 1),
            Self::I16 => compare_number!(i16, 2),
            Self::U16 => compare_number!(u16, 2),
            Self::I32 => compare_number!(i32, 4),
            Self::U32 => compare_number!(u32, 4),
            Self::I64 => compare_number!(i64, 8),
            Self::U64 => compare_number!(u64, 8),
            Self::F32 => compare_number!(f32, 4),
            Self::F64 => compare_number!(f64, 8),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanMode {
    Exact,
    Changed,
    Unchanged,
    Increased,
    Decreased,
}

impl ScanMode {
    pub const ALL: [Self; 5] = [
        Self::Exact,
        Self::Changed,
        Self::Unchanged,
        Self::Increased,
        Self::Decreased,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Exact => "Exact value",
            Self::Changed => "Changed",
            Self::Unchanged => "Unchanged",
            Self::Increased => "Increased",
            Self::Decreased => "Decreased",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ScanHit {
    pub address: usize,
    pub previous: Vec<u8>,
    pub current: Vec<u8>,
}

pub fn first_scan(
    pid: u32,
    value_type: ValueType,
    value: &[u8],
    limit: usize,
) -> Result<Vec<ScanHit>, String> {
    let process = ProcessMemory::open(pid)
        .map_err(|error| format!("could not open process {pid}: {error}"))?;
    let addresses = process
        .scan_exact(value, value_type.size(), limit)
        .map_err(|error| format!("scan failed: {error}"))?;
    Ok(addresses
        .into_iter()
        .map(|address| ScanHit {
            address,
            previous: value.to_vec(),
            current: value.to_vec(),
        })
        .collect())
}

pub fn next_scan(
    pid: u32,
    value_type: ValueType,
    hits: Vec<ScanHit>,
    mode: ScanMode,
    exact: Option<Vec<u8>>,
) -> Result<Vec<ScanHit>, String> {
    let process = ProcessMemory::open(pid)
        .map_err(|error| format!("could not open process {pid}: {error}"))?;
    let mut retained = Vec::new();

    for mut hit in hits {
        let Ok(current) = process.read(hit.address, value_type.size()) else {
            continue;
        };
        if current.len() != value_type.size() {
            continue;
        }

        let keep = match mode {
            ScanMode::Exact => exact.as_ref().is_some_and(|value| &current == value),
            ScanMode::Changed => current != hit.current,
            ScanMode::Unchanged => current == hit.current,
            ScanMode::Increased => {
                value_type.compare(&current, &hit.current) == Some(Ordering::Greater)
            }
            ScanMode::Decreased => {
                value_type.compare(&current, &hit.current) == Some(Ordering::Less)
            }
        };

        if keep {
            hit.previous = std::mem::replace(&mut hit.current, current);
            retained.push(hit);
        }
    }

    Ok(retained)
}

#[cfg(test)]
mod tests {
    use super::ValueType;

    #[test]
    fn parses_and_formats_values() {
        let bytes = ValueType::I32.parse("-123").unwrap();
        assert_eq!(ValueType::I32.format(&bytes), "-123");

        let bytes = ValueType::F32.parse("12.5").unwrap();
        assert_eq!(ValueType::F32.format(&bytes), "12.5");
    }
}
