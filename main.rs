use std::{env, ffi::c_void, io, mem::size_of, process::ExitCode};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::{
        Diagnostics::Debug::ReadProcessMemory,
        Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQueryEx},
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

const READ_CHUNK_SIZE: usize = 64 * 1024;

struct ProcessHandle(HANDLE);

impl ProcessHandle {
    fn open(pid: u32) -> io::Result<Self> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };

        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn scan(process: HANDLE, pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() {
        return None;
    }

    let mut cursor = 0usize;
    let mut buffer = vec![0u8; READ_CHUNK_SIZE];

    loop {
        let mut info = MEMORY_BASIC_INFORMATION::default();
        let queried = unsafe {
            VirtualQueryEx(
                process,
                cursor as *const c_void,
                &mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if queried == 0 {
            break;
        }

        let region_start = info.BaseAddress as usize;
        let Some(region_end) = region_start.checked_add(info.RegionSize) else {
            break;
        };

        let readable = info.State == MEM_COMMIT
            && info.Protect & PAGE_GUARD == 0
            && info.Protect & PAGE_NOACCESS == 0;

        if readable {
            let mut address = region_start;
            let mut overlap = Vec::new();

            while address < region_end {
                let bytes_to_read = READ_CHUNK_SIZE.min(region_end - address);
                let mut bytes_read = 0usize;
                let succeeded = unsafe {
                    ReadProcessMemory(
                        process,
                        address as *const c_void,
                        buffer.as_mut_ptr().cast(),
                        bytes_to_read,
                        &mut bytes_read,
                    )
                } != 0;

                if succeeded && bytes_read > 0 {
                    let combined_start = address - overlap.len();
                    overlap.extend_from_slice(&buffer[..bytes_read]);

                    if let Some(offset) = find_bytes(&overlap, pattern) {
                        return Some(combined_start + offset);
                    }

                    let overlap_size = pattern.len().saturating_sub(1).min(overlap.len());
                    overlap.drain(..overlap.len() - overlap_size);
                } else {
                    overlap.clear();
                }

                address = match address.checked_add(bytes_to_read) {
                    Some(next) => next,
                    None => break,
                };
            }
        }

        if region_end <= cursor {
            break;
        }
        cursor = region_end;
    }

    None
}

fn parse_pattern(input: &str) -> Result<Vec<u8>, String> {
    let mut digits = String::new();

    for token in input.split(|character: char| {
        character.is_ascii_whitespace() || character == ',' || character == '-'
    }) {
        let token = token
            .strip_prefix("0x")
            .or_else(|| token.strip_prefix("0X"))
            .unwrap_or(token);

        if !token.chars().all(|character| character.is_ascii_hexdigit()) {
            return Err(format!("invalid hex pattern: {input}"));
        }
        digits.push_str(token);
    }

    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return Err("the pattern must contain a non-zero, even number of hex digits".into());
    }

    (0..digits.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&digits[index..index + 2], 16).map_err(|error| error.to_string())
        })
        .collect()
}

fn run() -> Result<bool, String> {
    let mut arguments = env::args();
    let executable = arguments.next().unwrap_or_else(|| "hsgaurdian".into());
    let pid = arguments
        .next()
        .ok_or_else(|| format!("usage: {executable} <pid> <hex-pattern>"))?
        .parse::<u32>()
        .map_err(|error| format!("invalid PID: {error}"))?;
    let pattern = parse_pattern(
        &arguments
            .next()
            .ok_or_else(|| format!("usage: {executable} <pid> <hex-pattern>"))?,
    )?;

    if arguments.next().is_some() {
        return Err(format!("usage: {executable} <pid> <hex-pattern>"));
    }

    let process = ProcessHandle::open(pid)
        .map_err(|error| format!("could not open process {pid}: {error}"))?;

    match scan(process.0, &pattern) {
        Some(address) => {
            println!("Found pattern in process {pid} at 0x{address:X}");
            Ok(true)
        }
        None => {
            println!("Pattern was not found in process {pid}");
            Ok(false)
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{find_bytes, parse_pattern};

    #[test]
    fn parses_common_hex_formats() {
        assert_eq!(
            parse_pattern("DE AD BE EF").unwrap(),
            [0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert_eq!(
            parse_pattern("0xDE,0xAD,0xBE,0xEF").unwrap(),
            [0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert_eq!(parse_pattern("deadbeef").unwrap(), [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn rejects_invalid_hex() {
        assert!(parse_pattern("").is_err());
        assert!(parse_pattern("ABC").is_err());
        assert!(parse_pattern("GG").is_err());
    }

    #[test]
    fn finds_a_byte_sequence() {
        assert_eq!(find_bytes(&[1, 2, 3, 4], &[2, 3]), Some(1));
        assert_eq!(find_bytes(&[1, 2, 3, 4], &[5]), None);
    }
}
