use std::{ffi::c_void, io, mem::size_of};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::{
            Debug::{FlushInstructionCache, ReadProcessMemory, WriteProcessMemory},
            ToolHelp::{
                CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW,
                PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPMODULE,
                TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
            },
        },
        Memory::{PAGE_EXECUTE_READWRITE, VirtualProtectEx},
        Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
            PROCESS_VM_WRITE,
        },
    },
};

#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base: usize,
    pub size: usize,
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> io::Result<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub struct ProcessMemory {
    handle: OwnedHandle,
    pub writable: bool,
}

impl ProcessMemory {
    pub fn open(pid: u32) -> io::Result<Self> {
        let read_access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
        let write_access = read_access | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
        let writable_handle = unsafe { OpenProcess(write_access, 0, pid) };

        if let Ok(handle) = OwnedHandle::new(writable_handle) {
            return Ok(Self {
                handle,
                writable: true,
            });
        }

        let read_handle = unsafe { OpenProcess(read_access, 0, pid) };
        Ok(Self {
            handle: OwnedHandle::new(read_handle)?,
            writable: false,
        })
    }

    pub fn read(&self, address: usize, length: usize) -> io::Result<Vec<u8>> {
        if length == 0 {
            return Ok(Vec::new());
        }

        let mut bytes = vec![0u8; length];
        let mut bytes_read = 0usize;
        let succeeded = unsafe {
            ReadProcessMemory(
                self.handle.0,
                address as *const c_void,
                bytes.as_mut_ptr().cast(),
                length,
                &mut bytes_read,
            )
        } != 0;

        if !succeeded {
            return Err(io::Error::last_os_error());
        }

        bytes.truncate(bytes_read);
        Ok(bytes)
    }

    pub fn patch(&self, address: usize, replacement: &[u8]) -> io::Result<Vec<u8>> {
        if !self.writable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the process was attached read-only",
            ));
        }
        if replacement.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a patch cannot be empty",
            ));
        }

        let original = self.read(address, replacement.len())?;
        if original.len() != replacement.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "could not snapshot every byte before patching",
            ));
        }

        let mut old_protection = 0u32;
        let protected = unsafe {
            VirtualProtectEx(
                self.handle.0,
                address as *const c_void,
                replacement.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protection,
            )
        } != 0;
        if !protected {
            return Err(io::Error::last_os_error());
        }

        let mut bytes_written = 0usize;
        let write_succeeded = unsafe {
            WriteProcessMemory(
                self.handle.0,
                address as *mut c_void,
                replacement.as_ptr().cast(),
                replacement.len(),
                &mut bytes_written,
            )
        } != 0;
        let write_error = if write_succeeded && bytes_written == replacement.len() {
            None
        } else {
            Some(io::Error::last_os_error())
        };

        let mut ignored = 0u32;
        unsafe {
            VirtualProtectEx(
                self.handle.0,
                address as *const c_void,
                replacement.len(),
                old_protection,
                &mut ignored,
            );
        }

        if let Some(error) = write_error {
            return Err(error);
        }

        unsafe {
            FlushInstructionCache(self.handle.0, address as *const c_void, replacement.len());
        }
        Ok(original)
    }

    pub fn read_pointer(&self, address: usize, pointer_size: usize) -> io::Result<usize> {
        let bytes = self.read(address, pointer_size)?;
        match bytes.as_slice() {
            [a, b, c, d] => Ok(u32::from_le_bytes([*a, *b, *c, *d]) as usize),
            [a, b, c, d, e, f, g, h] => {
                Ok(u64::from_le_bytes([*a, *b, *c, *d, *e, *f, *g, *h]) as usize)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "could not read a complete pointer",
            )),
        }
    }

    pub fn resolve_pointer_chain(
        &self,
        base: usize,
        offsets: &[isize],
        pointer_size: usize,
    ) -> io::Result<Vec<usize>> {
        let mut current = base;
        let mut trace = vec![base];

        for (index, offset) in offsets.iter().copied().enumerate() {
            current = current.checked_add_signed(offset).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "pointer offset overflow")
            })?;
            trace.push(current);

            if index + 1 < offsets.len() {
                current = self.read_pointer(current, pointer_size)?;
                trace.push(current);
            }
        }

        Ok(trace)
    }
}

pub fn list_processes() -> io::Result<Vec<ProcessInfo>> {
    let snapshot = OwnedHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })?;
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut processes = Vec::new();

    if unsafe { Process32FirstW(snapshot.0, &mut entry) } == 0 {
        return Err(io::Error::last_os_error());
    }

    loop {
        processes.push(ProcessInfo {
            pid: entry.th32ProcessID,
            name: wide_string(&entry.szExeFile),
        });

        if unsafe { Process32NextW(snapshot.0, &mut entry) } == 0 {
            break;
        }
    }

    processes.sort_by_key(|process| process.name.to_ascii_lowercase());
    Ok(processes)
}

pub fn list_modules(pid: u32) -> io::Result<Vec<ModuleInfo>> {
    let snapshot = OwnedHandle::new(unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    })?;
    let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<MODULEENTRY32W>() as u32;
    let mut modules = Vec::new();

    if unsafe { Module32FirstW(snapshot.0, &mut entry) } == 0 {
        return Err(io::Error::last_os_error());
    }

    loop {
        modules.push(ModuleInfo {
            name: wide_string(&entry.szModule),
            path: wide_string(&entry.szExePath),
            base: entry.modBaseAddr as usize,
            size: entry.modBaseSize as usize,
        });

        if unsafe { Module32NextW(snapshot.0, &mut entry) } == 0 {
            break;
        }
    }

    modules.sort_by_key(|module| module.base);
    Ok(modules)
}

fn wide_string(buffer: &[u16]) -> String {
    let length = buffer
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..length])
}

pub fn parse_address(text: &str) -> Result<usize, String> {
    let trimmed = text.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    usize::from_str_radix(digits, 16).map_err(|error| format!("invalid address: {error}"))
}

pub fn parse_offsets(text: &str) -> Result<Vec<isize>, String> {
    text.split(|character: char| character == ',' || character.is_ascii_whitespace())
        .filter(|token| !token.is_empty())
        .map(parse_offset)
        .collect()
}

fn parse_offset(text: &str) -> Result<isize, String> {
    let (negative, unsigned) = text
        .strip_prefix('-')
        .map_or((false, text), |value| (true, value));
    let digits = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
        .unwrap_or(unsigned);
    let value = isize::from_str_radix(digits, 16)
        .map_err(|error| format!("invalid offset '{text}': {error}"))?;
    Ok(if negative { -value } else { value })
}

pub fn parse_hex_bytes(text: &str) -> Result<Vec<u8>, String> {
    let mut digits = String::new();
    for token in text.split(|character: char| {
        character.is_ascii_whitespace() || character == ',' || character == '-'
    }) {
        let token = token
            .strip_prefix("0x")
            .or_else(|| token.strip_prefix("0X"))
            .unwrap_or(token);
        if !token.chars().all(|character| character.is_ascii_hexdigit()) {
            return Err(format!("invalid hex bytes: {text}"));
        }
        digits.push_str(token);
    }

    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return Err("enter a non-empty, even number of hex digits".into());
    }

    (0..digits.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&digits[index..index + 2], 16).map_err(|error| error.to_string())
        })
        .collect()
}

pub fn format_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::{parse_address, parse_hex_bytes, parse_offsets};

    #[test]
    fn parses_addresses_and_offsets() {
        assert_eq!(parse_address("0x7FF0").unwrap(), 0x7FF0);
        assert_eq!(parse_offsets("10, -0x20 30").unwrap(), [0x10, -0x20, 0x30]);
    }

    #[test]
    fn parses_patch_bytes() {
        assert_eq!(parse_hex_bytes("90 90 CC").unwrap(), [0x90, 0x90, 0xCC]);
        assert_eq!(parse_hex_bytes("0x90,0xCC").unwrap(), [0x90, 0xCC]);
        assert!(parse_hex_bytes("GG").is_err());
    }
}
