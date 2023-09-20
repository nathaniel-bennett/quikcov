use std::sync::{OnceLock, Mutex};
use std::fs::File;
use std::os::fd::FromRawFd;
use std::collections::HashMap;

use fxhash::FxBuildHasher;

use crate::QUIKCOV_PIPE_ENV;

static IPC_WRITER: OnceLock<Mutex<File>> = OnceLock::new();
static GCDA_FILES: OnceLock<Mutex<HashMap<libc::c_int, FileInfo, FxBuildHasher>>> = OnceLock::new();

pub struct FileInfo {
    pub path: String,
    pub data: Vec<u8>,
}

pub fn ipc_writer() -> &'static Mutex<File> {
    IPC_WRITER.get_or_init(|| {
        let pipe_str = std::env::vars().find(|(key, _)| key == QUIKCOV_PIPE_ENV).expect("missing QUIKCOV_PIPE_ENV environment variable").1;
        let pipe_fd: i32 = pipe_str.parse().expect("QUIKCOV_PIPE_ENV must contain a positive integer indicating a pipe file descriptor");
        Mutex::new(unsafe { File::from_raw_fd(pipe_fd) })
    })
}

pub fn gcda_files() -> &'static Mutex<HashMap<libc::c_int, FileInfo, FxBuildHasher>> {
    GCDA_FILES.get_or_init(|| Mutex::new(HashMap::with_hasher(FxBuildHasher::default())))
}
