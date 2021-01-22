use winapi::shared::minwindef;

use std::os::windows::io::AsRawHandle;
use std::process::Child;
use std::ptr;

use super::{
    Architecture, CopyAddress, ProcessHandleExt, PutAddress, TryDetectArch, TryIntoProcessHandle,
};

/// On Windows a `Pid` is a `DWORD`.
pub type Pid = minwindef::DWORD;
/// On Windows a `ProcessHandle` is a `HANDLE`.
pub type ProcessHandle = (winapi::um::winnt::HANDLE, Architecture);

impl ProcessHandleExt for ProcessHandle {
    #[must_use]
    fn check_handle(&self) -> bool {
        self.0.is_null()
    }
    #[must_use]
    fn null_type() -> ProcessHandle {
        (ptr::null_mut(), Architecture::from_native())
    }
    #[must_use]
    fn set_arch(self, arch: Architecture) -> Self {
        (self.0, arch)
    }
}

/// Uses `winapi::um::wow64apiset::IsWow64Process` to figure out the architecture.
impl TryDetectArch for winapi::um::winnt::HANDLE {
    #[cfg(target_arch = "x86_64")]
    fn try_detect_arch(self) -> std::io::Result<Architecture> {
        let mut is_wow64 = 0_i32;

        if unsafe { winapi::um::wow64apiset::IsWow64Process(self, &mut is_wow64) } == 0 {
            return Err(std::io::Error::last_os_error());
        }

        // host=32, guest=32: FALSE
        // host=64, guest=32: TRUE
        // host=64, guest=64: FALSE
        if is_wow64 == minwindef::TRUE {
            Ok(Architecture::Arch32Bit)
        } else {
            Ok(Architecture::Arch64Bit)
        }
    }

    #[cfg(target_arch = "x86")]
    fn try_detect_arch(self) -> std::io::Result<Architecture> {
        Ok(Architecture::Arch32Bit)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    fn try_detect_arch(self) -> std::io::Result<Architecture> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Detecting architecture of remote process is not supported.",
        ))
    }
}

/// A `Pid` can be turned into a `ProcessHandle` with `OpenProcess`.
/// Attempts to detect architecture, returns error when detecting not supported.
impl TryIntoProcessHandle for minwindef::DWORD {
    fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle> {
        let handle = unsafe {
            winapi::um::processthreadsapi::OpenProcess(
                winapi::um::winnt::PROCESS_CREATE_THREAD
                    | winapi::um::winnt::PROCESS_QUERY_INFORMATION
                    | winapi::um::winnt::PROCESS_VM_READ
                    | winapi::um::winnt::PROCESS_VM_WRITE
                    | winapi::um::winnt::PROCESS_VM_OPERATION,
                winapi::shared::minwindef::FALSE,
                *self,
            )
        };

        if handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }

        Ok((handle, handle.try_detect_arch()?))
    }
}

/// A `std::process::Child` has a `HANDLE` from calling `CreateProcess`.
/// Attempts to detect architecture, returns error when detecting not supported.
impl TryIntoProcessHandle for Child {
    fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle> {
        let handle = self.as_raw_handle() as _;
        Ok((handle, handle.try_detect_arch()?))
    }
}

/// Use `ReadProcessMemory` to read memory from another process on Windows.
impl CopyAddress for ProcessHandle {
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn get_pointer_width(&self) -> Architecture {
        self.1
    }

    fn copy_address(&self, addr: usize, buf: &mut [u8]) -> std::io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        if unsafe {
            winapi::um::memoryapi::ReadProcessMemory(
                self.0,
                addr as minwindef::LPVOID,
                buf.as_mut_ptr() as minwindef::LPVOID,
                buf.len() as winapi::shared::basetsd::SIZE_T,
                ptr::null_mut(),
            )
        } == winapi::shared::minwindef::FALSE
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// Use `WriteProcessMemory` to write memory from another process on Windows.
impl PutAddress for ProcessHandle {
    fn put_address(&self, addr: usize, buf: &[u8]) -> std::io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        if unsafe {
            winapi::um::memoryapi::WriteProcessMemory(
                self.0,
                addr as minwindef::LPVOID,
                buf.as_ptr() as minwindef::LPCVOID,
                buf.len() as winapi::shared::basetsd::SIZE_T,
                ptr::null_mut(),
            )
        } == winapi::shared::minwindef::FALSE
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
