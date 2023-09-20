#![feature(c_variadic)]

use std::{ffi::CStr, io::Write};

use state::FileInfo;

extern crate libc;

mod hook_macros;
mod state;

pub const QUIKCOV_PIPE_ENV: &str = "QUIKCOV_LDPRELOAD_PIPE_FD";

// FIXME: what if the variadic argument `mode` isn't used? Could lead to UB...

hook_macros::hook! {
    unsafe fn openat(
        dirfd: libc::c_int,
        pathname: *const libc::c_char,
        flags: libc::c_int,
        ...
    ) -> libc::c_int => quikcov_openat {
        let ret = hook_macros::real!(openat)(dirfd, pathname, flags, ...);

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
}

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
