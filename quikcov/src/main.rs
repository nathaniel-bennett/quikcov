use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::prelude::OsStrExt;
use std::process::{Command, Stdio};

use clap::Parser;
use command_fds::FdMapping;
use command_fds::CommandFdExt;
use fxhash::FxBuildHasher;
use quikcov_common::prelude::*;
use serde::{Deserialize, Serialize};

const QUIKCOV_PIPE_ENV: &str = "QUIKCOV_LDPRELOAD_PIPE_FD";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The directory containing the source code of the program
    #[arg(long, value_name = "PATH")]
    source_path: String,
    /// The directory containing .gcno and .gcda files for the program
    #[arg(long, value_name = "PATH")]
    cov_path: String,
    /// The LD_PRELOAD library to load
    #[arg(long, value_name = "PATH")]
    preload_path: String,
    // The directory containing seed files to be tested in alphabetic order
    #[arg(long, value_name = "PATH")]
    seed_queue: String,
    /// The directory to store results in
    #[arg(short, long, value_name = "PATH")]
    output: String,
    /// The command (and optionally arguments) that will run fuzzing
    #[arg(required = true)]
    fuzz_command: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct Gcda {
    filepath: String,
    data: Vec<u8>,
}

fn main() {
    let args = Args::parse();

    // Clear any old .gcda files
    Command::new("find")
        .args([args.cov_path.as_str(), "-name", "*.gcda", "-delete"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output().unwrap();

    // Gather all .gcno files
    let gcno_output = Command::new("find")
        .args([args.cov_path.as_str(), "-name", "*.gcno"])
        .stderr(Stdio::null())
        .output().unwrap();

    let mut cov_builders = HashMap::with_hasher(FxBuildHasher::default());

    for cov_path in String::from_utf8(gcno_output.stdout).unwrap().split('\n') {
        let gcno_file = cov_path.trim();
        if gcno_file.is_empty() {
            continue
        }

        let gcno_bytes = fs::read(gcno_file).unwrap();
        if gcno_bytes.is_empty() {
            continue
        }
        let gcno = Gcno::from_slice(&gcno_bytes).unwrap();

        // FIXME: this is brittle if any other part of the file path has .gcno in it
        let gcda_file = cov_path.replace(".gcno", ".gcda");

        cov_builders.insert(gcda_file, FileCovBuilder::new(gcno));
    }

    // Collect list of files to run fuzzer on
    let mut sorted_seed_files: Vec<_> = fs::read_dir(args.seed_queue).unwrap().map(|file| file.unwrap()).collect();
    sorted_seed_files.sort_by_key(|file| file.path());

    for (idx, seed_file) in sorted_seed_files.into_iter().enumerate() {
        let seed_pathname = seed_file.path().to_str().unwrap().to_string();
        if seed_pathname.contains("README.md") || seed_file.path().is_dir() || seed_file.path().file_name().unwrap().as_bytes()[0] == b'.' {
            continue // Ignore README, dirs, and hidden files
        }

        println!("Testing seed `{}`", seed_pathname);
        let cmd = &args.fuzz_command[0]; // FIXME: brittle
        let cmd_args = &args.fuzz_command[1..];

        let (mut parent_read_pipe, child_write_pipe) = os_pipe::pipe().unwrap();
        let mut process = Command::new(cmd)
            .args(cmd_args)
            .env("LD_PRELOAD", &args.preload_path)
            .env(QUIKCOV_PIPE_ENV, format!("{}", child_write_pipe.as_raw_fd()))
            .fd_mappings(vec! [
                FdMapping {
                    parent_fd: child_write_pipe.as_raw_fd(),
                    child_fd: child_write_pipe.as_raw_fd(),
                }
            ]).unwrap()
            .stdin(Stdio::from(fs::File::open(seed_pathname).unwrap()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn().unwrap();
        drop(child_write_pipe);

        let mut more_to_read = [0u8; 1];
        while parent_read_pipe.read(&mut more_to_read).unwrap() != 0 {
            let mut length_arr = [0u8; 4];
            parent_read_pipe.read_exact(&mut length_arr).unwrap();
            let length = u32::from_be_bytes(length_arr) as usize;

            let mut gcda_bytes = Vec::new();
            gcda_bytes.reserve(length);
            gcda_bytes.extend(std::iter::repeat(0u8).take(length));

            let gcda: Gcda = postcard::from_bytes(&gcda_bytes).unwrap();
            println!("Received gcda file {}", &gcda.filepath);
            let builder = cov_builders.get_mut(&gcda.filepath).unwrap();
            builder.add_gcda(&gcda.data).unwrap();
        }

        let Some(coverage) = cov_builders.iter().map(|(_, builder)| builder.clone().build().unwrap()).reduce(|mut a, b| { a.merge(b).unwrap(); a }) else {
            panic!("no .gcno files found");
        };

        let mut total_covered = 0;
        let mut total_blocks = 0;
        for file in coverage.files.values() {
            for function in file.fns.values() {
                total_covered += function.executed_blocks;
                total_blocks += function.total_blocks;
            }
        }

        //let json_out = serde_json::to_vec(&coverage).unwrap();
        //std::fs::write(format!("{}/{}.coverage", &args.output, idx), json_out).unwrap();

        println!("Covered {} blocks out of {} ({}%)", total_covered, total_blocks, (total_covered * 100) as f64 / (total_blocks as f64));
        // Make sure the old process has died before starting another
        process.wait().unwrap();
    }
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




