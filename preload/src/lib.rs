//#![feature(c_variadic)]

use std::{ffi::CStr, io::Write};

use state::Gcda;

extern crate libc;

mod hook_macros;
mod state;

pub const QUIKCOV_PIPE_ENV: &str = "QUIKCOV_LDPRELOAD_PIPE_FD";

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
                let mut gcda_files = state::gcda_files().lock().unwrap();
                gcda_files.insert(fd, Gcda {
                    filepath: path_cstr.to_str().unwrap().to_string(),
                    data: Vec::new(),
                });
                drop(gcda_files);
            }
        }

        fd
    }
}

hook_macros::hook! {
    unsafe fn fdopen(
        fd: libc::c_int,
        mode: *const libc::c_char
    ) -> *mut libc::FILE => quikcov_fdopen {
        let file = hook_macros::real!(fdopen)(fd, mode);

        if file != std::ptr::null_mut() {
            let file_ptr_value = file as usize;
            let mut fd_map = state::fd_map().lock().unwrap();
            fd_map.insert(file_ptr_value, fd);
            drop(fd_map);
        }

        file
    }
}

hook_macros::hook! {
    unsafe fn write(
        fd: libc::c_int,
        buf: *const libc::c_void,
        count: libc::size_t
    ) -> libc::ssize_t => quikcov_write {
        let mut gcda_files = state::gcda_files().lock().unwrap();
        if let Some(gcda_file) = gcda_files.get_mut(&fd) {
            gcda_file.data.extend_from_slice(std::slice::from_raw_parts(buf as *const u8, count));
            drop(gcda_files);
            count as isize
        } else {
            drop(gcda_files);
            hook_macros::real!(write)(fd, buf, count)
        }
    }
}


hook_macros::hook! {
    unsafe fn fwrite(
        ptr: *mut libc::c_void,
        size: libc::size_t,
        nmemb: libc::size_t,
        stream: *mut libc::FILE
    ) -> libc::size_t => quikcov_fwrite {
        let mut fd_map = state::fd_map().lock().unwrap();
        if let Some(&fd) = fd_map.get(&(stream as usize)) {
            drop(fd_map);
            let mut gcda_files = state::gcda_files().lock().unwrap();
            if let Some(gcda_file) = gcda_files.get_mut(&fd) {
                gcda_file.data.extend_from_slice(std::slice::from_raw_parts(ptr as *const u8, size * nmemb));
                drop(gcda_files);
                return nmemb as usize
            } else {
                drop(gcda_files);
            }
        } else {
            drop(fd_map);
        }
        hook_macros::real!(fwrite)(ptr, size, nmemb, stream)
    }
}

hook_macros::hook! {
    unsafe fn fclose(
        stream: *mut libc::FILE
    ) -> libc::c_int => quikcov_fclose {
        let mut fd_map = state::fd_map().lock().unwrap();
        if let Some(fd) = fd_map.remove(&(stream as usize)) {
            drop(fd_map);
            // This locks up for some reason...
            let mut gcda_files = state::gcda_files().lock().unwrap();
            if let Some(gcda_file) = gcda_files.remove(&fd) {
                drop(gcda_files);

                let gcda_bytes = postcard::to_stdvec(&gcda_file).unwrap();
                let mut ipc_writer = state::ipc_writer().lock().unwrap();

                ipc_writer.write_all([0u8; 1].as_slice()).unwrap();
                ipc_writer.write_all((gcda_bytes.len() as u32).to_be_bytes().as_slice()).unwrap();
                ipc_writer.write_all(gcda_bytes.as_slice()).unwrap();
                drop(ipc_writer);
            } else {
                drop(gcda_files);
            }
        } else {
            drop(fd_map);
        }

        hook_macros::real!(fclose)(stream)
    }
}
