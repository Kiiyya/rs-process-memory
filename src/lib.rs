//! This crate provides tools for working with the raw memory of programs.
//!
//! Some examples of use cases for this tool are:
//!  - Remote debugging tools
//!  - Game "trainers"
//!  - Rust clones of Cheat Engine
//!
//! ## Examples
//! ```rust
//! # use process_memory::{Memory, DataMember, Pid, TryIntoProcessHandle};
//! // We have a variable with some value
//! let x = 4_u32;
//! println!("Original x-value: {}", x);
//!
//! // We need to make sure that we get a handle to a process, in this case, ourselves
//! let handle = (std::process::id() as Pid).try_into_process_handle().unwrap();
//! // We make a `DataMember` that has an offset referring to its location in memory
//! let member = DataMember::new_offset(handle, vec![&x as *const _ as usize]);
//! // The memory refered to is now the same
//! println!("Memory location: &x: {}, member: {}", &x as *const _ as usize,
//!     member.get_offset().unwrap());
//! assert_eq!(&x as *const _ as usize, member.get_offset().unwrap());
//! // The value of the member is the same as the variable
//! println!("Member value: {}", member.read().unwrap());
//! assert_eq!(x, member.read().unwrap());
//! // We can write to and modify the value of the variable using the member
//! member.write(&6_u32).unwrap();
//! println!("New x-value: {}", x);
//! assert_eq!(x, 6_u32);
//! ```
//! ```rust
//! # use process_memory::{Memory, LocalMember};
//! // We have a variable with some value
//! let x = 4_u32;
//! println!("Original x-value: {}", x);
//!
//! // We make a `LocalMember` that has an offset referring to its location in memory
//! let member = LocalMember::new_offset(vec![&x as *const _ as usize]);
//! // The memory refered to is now the same
//! println!("Memory location: &x: {}, member: {}", &x as *const _ as usize,
//!     member.get_offset().unwrap());
//! assert_eq!(&x as *const _ as usize, member.get_offset().unwrap());
//! // The value of the member is the same as the variable
//! println!("Member value: {}", member.read().unwrap());
//! assert_eq!(x, member.read().unwrap());
//! // We can write to and modify the value of the variable using the member
//! member.write(&6_u32).unwrap();
//! println!("New x-value: {}", x);
//! assert_eq!(x, 6_u32);
//! ```
//! ```no_run
//! # use process_memory::{Architecture, Memory, DataMember, Pid, ProcessHandleExt, TryIntoProcessHandle};
//! # fn get_pid(process_name: &str) -> Pid {
//! #     std::process::id() as Pid
//! # }
//! // We get a handle for a target process with a different architecture to ourselves
//! let handle = get_pid("32Bit.exe").try_into_process_handle().unwrap()
//!     .set_arch(Architecture::Arch32Bit);
//! // We make a `DataMember` that has a series of offsets refering to a known value in
//! // the target processes memory
//! let member = DataMember::new_offset(handle, vec![0x01_02_03_04, 0x04, 0x08, 0x10]);
//! // The memory offset can now be correctly calculated:
//! println!("Target memory location: {}", member.get_offset().unwrap());
//! // The memory offset can now be used to retrieve and modify values:
//! println!("Current value: {}", member.read().unwrap());
//! member.write(&123_u32).unwrap();
//! ```
#![deny(missing_docs)]
#![deny(unused_results)]
#![deny(unreachable_pub)]
#![deny(missing_debug_implementations)]
#![deny(rust_2018_idioms)]
#![deny(bad_style)]
#![deny(unused)]
#![deny(clippy::pedantic)]

mod architecture;
mod data_member;
mod local_member;

pub use architecture::Architecture;
pub use data_member::DataMember;
pub use local_member::LocalMember;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod platform;
#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod platform;
#[cfg(windows)]
#[path = "windows.rs"]
mod platform;

/// A trait that defines that it is possible to copy some memory from something represented by a
/// type into a buffer.
pub trait CopyAddress {
    /// Copy an address into user-defined buffer.
    ///
    /// # Errors
    /// `std::io::Error` if an error occurs copying the address.
    fn copy_address(&self, addr: usize, buf: &mut [u8]) -> std::io::Result<()>;

    /// Get the actual memory location from a set of offsets.
    ///
    /// If [`copy_address`] and [`get_pointer_width`] are already defined, then
    /// we can provide a standard implementation that will work across all
    /// operating systems.
    ///
    /// # Errors
    /// `std::io::Error` if an error occurs copying the address.
    fn get_offset(&self, offsets: &[usize]) -> std::io::Result<usize> {
        // Look ma! No unsafes!
        let mut offset: usize = 0;
        let noffsets: usize = offsets.len();
        let mut copy = vec![0_u8; self.get_pointer_width() as usize];
        for next_offset in offsets.iter().take(noffsets - 1) {
            offset = offset.wrapping_add(*next_offset);
            self.copy_address(offset, &mut copy)?;
            offset = self.get_pointer_width().pointer_from_ne_bytes(&copy);
        }

        offset = offset.wrapping_add(offsets[noffsets - 1]);
        Ok(offset)
    }

    /// Get the the pointer width of the underlying process.
    /// This is required for [`get_offset`] to work.
    ///
    /// # Performance
    /// Any implementation of this function should be marked with
    /// `#[inline(always)]` as this function is *very* commonly called and
    /// should be inlined.
    fn get_pointer_width(&self) -> Architecture;
}

/// A trait that defines that it is possible to put a buffer into the memory of something
/// represented by a type.
pub trait PutAddress {
    /// Put the data from a user-defined buffer at an address.
    ///
    /// # Errors
    /// `std::io::Error` if an error occurs copying the address.
    fn put_address(&self, addr: usize, buf: &[u8]) -> std::io::Result<()>;
}

/// A `Pid` is a "process id". Each different platform has a different method for uniquely
/// identifying a process. You can see what the Rust standard library uses for your platform by
/// looking at `std::process::id`.
pub use platform::Pid;
/// A `ProcessHandle` is a variable type that allows for access to functions that can manipulate
/// other processes. On platforms other than Linux, this is typically a different type than
/// [`Pid`], and thus it is a distinct type here.
///
/// [`Pid`]: type.Pid.html
pub use platform::ProcessHandle;

/// Attempt to detect the architecture of a process (e.g. whether it's 32bit or 64bit).
pub trait TryDetectArch {
    /// Attempt to detect the architecture of a process (e.g. whether it's 32bit or 64bit).
    /// # Errors
    /// Returns an `std::io::Error` with `Other` `ErrorKind` when detecting architecture of
    /// the other process is not possible or not yet implemented.
    fn try_detect_arch(self) -> std::io::Result<Architecture>;
}

/// A trait that attempts to turn some type into a [`ProcessHandle`] so memory can be either copied
/// or placed into it.
///
/// [`ProcessHandle`]: type.ProcessHandle.html
pub trait TryIntoProcessHandle {
    /// Attempt to turn a type into a [`ProcessHandle`]. Whilst Linux provides the same type for
    /// [`Pid`]s and [`ProcessHandle`]s, Windows and macOS do not. As such, you need to ensure that
    /// `try_into_process_handle` is called on all [`Pid`]s to ensure cross-platform capabilities.
    ///
    /// # Errors
    /// Returns an error if the type cannot be turned into a [`ProcessHandle`]
    ///
    /// [`ProcessHandle`]: type.ProcessHandle.html
    /// [`Pid`]: type.Pid.html
    fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle>;
}

impl TryIntoProcessHandle for ProcessHandle {
    fn try_into_process_handle(&self) -> std::io::Result<platform::ProcessHandle> {
        Ok(*self)
    }
}

/// Additional functions on process handles
pub trait ProcessHandleExt {
    /// Returns `true` if the `ProcessHandle` is not null, and `false` otherwise.
    fn check_handle(&self) -> bool;
    /// Return the null equivalent of a `ProcessHandle`.
    #[must_use]
    fn null_type() -> ProcessHandle;
    /// Set this handle to use some architecture
    #[must_use]
    fn set_arch(self, arch: Architecture) -> Self;
}

/// Getting some information (such as base address) of loaded libraries in a process.
pub trait GetLibraryInfo {
    /// Lists all loaded libraries in a given process.
    /// You can then use the address in [`set_offset`] for example.
    /// On Windows, libraries are also called "modules", and usually end in `*.dll`.
    /// On Linux and macOS, libraries are also called "shared library", and usually end in `*.so`.
    ///
    /// # Errors
    /// Returns OS Error when something else went wrong.
    /// Returns other error when closing the handle fails.
    ///
    /// [`set_offset`]: trait.Memory.html#tymethod.set_offset
    fn libs_iter(&self) -> std::io::Result<Vec<LibraryInfo>>;

    /// Finds the base address of a loaded library in a process.
    /// You can then use the address in [`set_offset`] for example.
    /// On Windows, libraries are also called "modules", and usually end in `*.dll`.
    /// On Linux and macOS, libraries are also called "shared library", and usually end in `*.so`.
    ///
    /// # Errors
    /// Returns OS Error when something else went wrong.
    /// Returns other error when closing the handle fails.
    /// Returns a `NotFound` when no such library is loaded.
    ///
    /// [`set_offset`]: trait.Memory.html#tymethod.set_offset
    fn get_library_base(&self, name: &str) -> std::io::Result<usize> {
        match self.libs_iter()?.iter().find(|p| p.name == name) {
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Count not find base address of library \"{}\"", name),
            )),
            Some(lib) => Ok(lib.base),
        }
    }
}

/// A trait that refers to and allows writing to a region of memory in a running program.
pub trait Memory<T> {
    /// Set the offsets to the location in memory. This is used for things such as multi-level
    /// pointers, such as a `Vec<Vec<T>>` or a `Vec<String>`.
    ///
    /// For those sorts of data structures, to access data you need to go via multiple pointers, so
    /// that if an inner region reallocates its size, the variable that is being modified will be
    /// correctly modified.
    fn set_offset(&mut self, new_offsets: Vec<usize>);

    /// Gets the actual total offset from the offsets given by [`Memory::set_offset`].
    ///
    /// This function is safe because it should never internally allow for a null pointer
    /// deference, and instead should return a `std::io::Error` with a `std::io::ErrorKind` of
    /// `Other`.
    ///
    /// # Errors
    /// Returns an error if copying memory fails or if a null pointer dereference would
    /// otherwise occur.
    ///
    /// [`Memory::set_offset`]: trait.Memory.html#tymethod.set_offset
    fn get_offset(&self) -> std::io::Result<usize>;

    /// Reads the value of the pointer from the offsets given by [`Memory::set_offset`].
    ///
    /// This function is safe because it should never internally allow for a null pointer
    /// deference, and instead should return a `std::io::Error` with a `std::io::ErrorKind` of
    /// `Other`.
    ///
    /// # Errors
    /// Returns an error if copying memory fails or if a null pointer dereference would
    /// otherwise occur.
    ///
    /// [`Memory::set_offset`]: trait.Memory.html#tymethod.set_offset
    fn read(&self) -> std::io::Result<T>;

    /// Writes `value` to the pointer from the offsets given by [`Memory::set_offset`].
    ///
    /// This function is safe because it should never internally allow for a null pointer
    /// deference, and instead should return a `std::io::Error` with a `std::io::ErrorKind` of
    /// `Other`.
    ///
    /// This function takes a reference instead of taking ownership so if the caller passes in a
    /// `String` or a `Vec`, it does not have to be cloned.
    ///
    /// # Errors
    /// Returns an error if copying memory fails or if a null pointer dereference would
    /// otherwise occur.
    ///
    /// [`Memory::set_offset`]: trait.Memory.html#tymethod.set_offset
    fn write(&self, value: &T) -> std::io::Result<()>;
}

/// Copy `length` bytes of memory at `addr` from `source`.
///
/// This is just a convenient way to call `CopyAddress::copy_address` without
/// having to provide your own buffer.
///
/// # Errors
/// Returns an error if copying memory fails
pub fn copy_address<T>(addr: usize, length: usize, source: &T) -> std::io::Result<Vec<u8>>
where
    T: CopyAddress,
{
    let mut copy = vec![0; length];

    source.copy_address(addr, &mut copy)?;
    Ok(copy)
}

/// A minimal amount of information about a system process.
#[derive(Debug)]
pub struct ProcessInfo {
    /// Process ID of this process.
    pub pid: Pid,
    /// Name of this process. For example "MyGame.exe" on Windows.
    pub name: String,
}

#[cfg(windows)]
pub use platform::processes_iter;

/// A minimal amount of information about a library inside another process.
/// On Windows, libraries are also called "modules", and usually end in `*.dll`.
/// On Linux and macOS, libraries are also called "shared library", and usually end in `*.so`.
#[derive(Debug)]
pub struct LibraryInfo {
    /// Name of the library.
    pub name: String,
    /// Base address of the module in the remote process.
    pub base: usize,
}
