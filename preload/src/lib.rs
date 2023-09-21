//#![feature(c_variadic)]

use std::{ffi::CStr, io::Write};

use state::FileInfo;

extern crate libc;

mod hook_macros;
mod state;

pub const QUIKCOV_PIPE_ENV: &str = "QUIKCOV_LDPRELOAD_PIPE_FD";

// FIXME: what if the variadic argument `mode` isn't used? Could lead to UB...


hook_macros::hook! {
    unsafe fn open(
        pathname: *const libc::c_char,
        flags: libc::c_int,
        mode: libc::mode_t
    ) -> libc::c_int => quikcov_open {
        let fd = hook_macros::real!(open)(pathname, flags, mode);

        if fd >= 0 {
            let path_cstr = unsafe { CStr::from_ptr(pathname) };
            let len = path_cstr.to_bytes().len();

            let is_gcda = path_cstr.to_bytes().get(len.saturating_sub(5)..).map(|suffix| suffix == b".gcda".as_slice()).unwrap_or(false);

            if is_gcda {
                println!("observed .gcda file opening: {}", path_cstr.to_str().unwrap());
                state::gcda_files().lock().unwrap().insert(fd, FileInfo {
                    path: path_cstr.to_str().unwrap().to_string(),
                    data: Vec::new(),
                });
            }
        }

        fd
    }
}


// We can't use hook_macros::hook! here as it doesn't support variadics

/*
pub struct OpenatStruct {__private_field: ()}
static OPENAT_CONST: OpenatStruct = OpenatStruct {__private_field: ()};

impl OpenatStruct {
    fn get(&self) -> unsafe extern fn (dirfd: libc::c_int, pathname: *const libc::c_char, flags: libc::c_int, args: ...) -> libc::c_int {
        use ::std::sync::Once;

        static mut REAL: *const u8 = 0 as *const u8;
        static mut ONCE: Once = Once::new();

        unsafe {
            ONCE.call_once(|| {
                REAL = hook_macros::ld_preload::dlsym_next(concat!(stringify!($real_fn), "\0"));
            });
            ::std::mem::transmute(REAL)
        }
    }   
}

#[no_mangle]
pub unsafe extern fn openat(dirfd: libc::c_int, pathname: *const libc::c_char, flags: libc::c_int, args: ...) -> libc::c_int {
    let orig_hook = std::panic::take_hook();

    // in case openat_quikcov panics, this will immediately abort rather than unwinding and causing UB.
    std::panic::set_hook(Box::new(move |panic_info| {
        std::process::abort()
    }));
    let ret = openat_quikcov(dirfd, pathname, flags, args);

    // Reset the panic handler hook
    std::panic::set_hook(orig_hook);
    
    ret
}

pub unsafe extern fn openat_quikcov(dirfd: libc::c_int, pathname: *const libc::c_char, flags: libc::c_int, args: ...) -> libc::c_int {
    let ret = OPENAT_CONST.get()(dirfd, pathname, flags, args);

    let path_cstr = unsafe { CStr::from_ptr(pathname) };
    let len = path_cstr.to_bytes().len();

    let is_gcda = path_cstr.to_bytes().get(len.saturating_sub(5)..).map(|suffix| suffix == b".gcda".as_slice()).unwrap_or(false);

    if is_gcda && ret >= 0 {
        state::gcda_files().lock().unwrap().insert(ret, FileInfo {
            path: path_cstr.to_str().unwrap().to_string(),
            data: Vec::new(),
        });
    }

    ret
}
*/





hook_macros::hook! {
    unsafe fn write(
        fd: libc::c_int,
        buf: *const libc::c_void,
        count: libc::size_t
    ) -> libc::ssize_t => quikcov_write {
        if let Some(gcda_file) = state::gcda_files().lock().unwrap().get_mut(&fd) {
            gcda_file.data.extend_from_slice(std::slice::from_raw_parts(buf as *const u8, count));
            count as isize
        } else {
            hook_macros::real!(write)(fd, buf, count)
        }
    }
}

hook_macros::hook! {
    unsafe fn close(
        fd: libc::c_int
    ) -> libc::ssize_t => quikcov_close {
        
        if let Some(gcda_file) = state::gcda_files().lock().unwrap().remove(&fd) {
            // TODO: could add filename here...
            let file_len = gcda_file.data.len();
            let mut ipc_writer = state::ipc_writer().lock().unwrap();
            ipc_writer.write_all(file_len.to_be_bytes().as_slice()).unwrap();
            ipc_writer.write_all(gcda_file.data.as_slice()).unwrap();
        }
        
        hook_macros::real!(close)(fd)
    }
}
