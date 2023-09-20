use std::{process::Command, os::fd::AsRawFd};

use command_fds::FdMapping;
use command_fds::CommandFdExt;
use quikcov_common::prelude::*;

const QUIKCOV_PIPE_ENV: &str = "QUIKCOV_LDPRELOAD_PIPE_FD";

fn main() {
    let cmd = "whoami";
    let args: Vec<String> = Vec::new();

    let (parent_read_pipe, child_write_pipe) = os_pipe::pipe().unwrap();

    let process = Command::new(cmd)
        .args(args)
        // FIXME: add ld_preload env here
        .env(QUIKCOV_PIPE_ENV, format!("{}", child_write_pipe.as_raw_fd()))
        .fd_mappings(vec! [
            FdMapping {
                parent_fd: child_write_pipe.as_raw_fd(),
                child_fd: child_write_pipe.as_raw_fd(),
            }
        ]).unwrap()
        .spawn().unwrap();
    drop(child_write_pipe);
}



fn test() {
    env_logger::init();
    let mut args = std::env::args();

    if args.len() != 4 {
        println!("Usage: quikcov <gcno> <gcda> <outfile>");
        return
    }
    args.next();
    let gcno_file = args.next().unwrap().to_string();
    let gcda_file = args.next().unwrap().to_string();
    let outfile = args.next().unwrap().to_string();
    
    let gcno_bytes = std::fs::read(gcno_file).unwrap();
    let gcda_bytes = std::fs::read(gcda_file).unwrap();

    let gcno = Gcno::from_slice(gcno_bytes.as_slice()).unwrap();
    let mut cov_builder = FileCovBuilder::new(gcno);
    cov_builder.add_gcda(gcda_bytes.as_slice()).unwrap();
    let cov = cov_builder.build().unwrap();

//    let bytes: Vec<u8> = postcard::to_stdvec(&cov).unwrap();
    let bytes = serde_json::to_vec(&cov).unwrap();
    std::fs::write(outfile, bytes).unwrap();
}




