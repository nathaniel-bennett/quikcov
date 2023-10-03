use std::sync::{OnceLock, Mutex};
use std::os::fd::RawFd;
use std::collections::HashMap;

use fxhash::FxBuildHasher;
use serde::{Deserialize, Serialize};

use crate::QUIKCOV_PIPE_ENV;

static IPC_WRITER: OnceLock<Mutex<RawFd>> = OnceLock::new();
static GCDA_FILES: OnceLock<Mutex<HashMap<libc::c_int, Gcda, FxBuildHasher>>> = OnceLock::new();
static FD_MAP: OnceLock<Mutex<HashMap<usize, libc::c_int, FxBuildHasher>>> = OnceLock::new();


#[derive(Deserialize, Serialize)]
pub struct Gcda {
    pub filepath: String,
    pub data: Vec<u8>,
}

pub fn ipc_writer() -> &'static Mutex<RawFd> {
    IPC_WRITER.get_or_init(|| {
        let pipe_str = std::env::vars().find(|(key, _)| key == QUIKCOV_PIPE_ENV).expect("missing QUIKCOV_PIPE_ENV environment variable").1;
        let pipe_fd: i32 = pipe_str.parse().expect("QUIKCOV_PIPE_ENV must contain a positive integer indicating a pipe file descriptor");
        Mutex::new(RawFd::from(pipe_fd))
    })
}

pub fn gcda_files() -> &'static Mutex<HashMap<libc::c_int, Gcda, FxBuildHasher>> {
    GCDA_FILES.get_or_init(|| Mutex::new(HashMap::with_hasher(FxBuildHasher::default())))
}

pub fn fd_map() -> &'static Mutex<HashMap<usize, libc::c_int, FxBuildHasher>> {
    FD_MAP.get_or_init(|| Mutex::new(HashMap::with_hasher(FxBuildHasher::default())))
}
