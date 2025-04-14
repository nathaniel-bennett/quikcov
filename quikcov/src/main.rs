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
/*
    /// The directory containing the source code of the program
    #[arg(long, value_name = "PATH")]
    source_path: String,
*/
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
    /// Instructs quikcov to prepend any absolute path reported in .gcno/.gcda files to the function location
    #[arg(short, long)]
    abs_path: bool,
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
    env_logger::init();
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

        log::debug!("reading .gcno file \"{}\"", gcno_file);

        let gcno_bytes = fs::read(gcno_file).unwrap();
        if gcno_bytes.is_empty() {
            continue
        }

        let gcno = Gcno::from_slice(&gcno_bytes).unwrap();

        // FIXME: this is brittle if any other part of the file path has .gcno in it

        let mut gcda_file = cov_path.replace(".gcno", ".gcda");
        if args.abs_path {
            let Some(cwd_path) = gcno.cwd.clone() else {
                panic!("abs-path flag set but no cwd located in .gcno files");
            };
            gcda_file = format!("{}/{}", cwd_path, gcda_file).replace("//", "/");
        }

        cov_builders.insert(gcda_file, FileCovBuilder::new(gcno));
    }

    // Collect list of files to run fuzzer on
    let mut sorted_seed_files: Vec<_> = fs::read_dir(args.seed_queue).unwrap().map(|file| file.unwrap()).collect();
    sorted_seed_files.sort_by_key(|file| file.path());

    let mut prev_total_covered = 0;
    for (idx, seed_file) in sorted_seed_files.into_iter().enumerate() {
        let seed_pathname = seed_file.path().to_str().unwrap().to_string();
        if seed_pathname.contains("README.md") || seed_file.path().is_dir() || seed_file.path().file_name().unwrap().as_bytes()[0] == b'.' {
            continue // Ignore README, dirs, and hidden files
        }

        log::info!("Testing seed file \"{}\"", seed_pathname);
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

        let mut gcda_bytes = Vec::new();

        let mut more_to_read = [0u8; 1];
        while parent_read_pipe.read(more_to_read.as_mut_slice()).unwrap() != 0 {
            let mut length_arr = [0u8; 4];
            if let Err(e) = parent_read_pipe.read_exact(&mut length_arr) {
                log::error!("Notify pipe failed during reading of coverage ({:?})--program likely crashed. Skipping testcase...", e);
                break
            }
            let length = u32::from_be_bytes(length_arr) as usize;

            if length > gcda_bytes.len() {
                gcda_bytes.reserve(length - gcda_bytes.len());
                gcda_bytes.extend(std::iter::repeat(0u8).take(length - gcda_bytes.len()));
            }

            if let Err(e) = parent_read_pipe.read_exact(&mut gcda_bytes[..length]) {
                log::error!("Notify pipe failed during reading of coverage--program likely crashed. Skipping testcase...");
                break
            }

            let Ok(gcda) = postcard::from_bytes::<Gcda>(&gcda_bytes[..length]) else {
                log::error!("postcard failed to interpret bytes passed from notify pipe. Skipping testcase...");
                break
            };

            log::info!("received .gcda file: {:?}", &gcda.filepath);

            let Some(builder) = cov_builders.get_mut(&gcda.filepath) else {
                log::warn!("file {} not found--skipping", &gcda.filepath);
                continue
            };

            if let Err(e) = builder.add_gcda(&gcda.data) {
                log::error!(".gcda file couldn't be added to builder: {:?}. Skipping...", e);
                continue
            }
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

        if prev_total_covered != total_covered {
            prev_total_covered = total_covered;
            let json_out = serde_json::to_vec(&CoverageOne::new(coverage)).unwrap();
            std::fs::write(format!("{}/{}.coverage.json", &args.output, idx), json_out).unwrap();
        }

        println!("{}: Covered {} blocks out of {} ({:.2}%)", idx, total_covered, total_blocks, (total_covered * 100) as f64 / (total_blocks as f64));
        // Make sure the old process has died before starting another
        process.wait().unwrap();
    }
}

#[derive(Deserialize, Serialize)]
struct CoverageOne {
    covered_blocks: usize,
    total_blocks: usize,
    files: HashMap<String, CoverageFile, FxBuildHasher>,
}

impl CoverageOne {
    pub fn new(cov: ProgCoverage) -> Self {
        let mut covered_blocks = 0;
        let mut total_blocks = 0;
        let mut files = HashMap::with_hasher(FxBuildHasher::default());
        for (name, file) in cov.files {
            let cov_file = CoverageFile::new(file);
            covered_blocks += cov_file.covered_blocks;
            total_blocks += cov_file.total_blocks;
            files.insert(name, cov_file);
        }

        Self {
            covered_blocks,
            total_blocks,
            files,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct CoverageFile {
    covered_blocks: usize,
    total_blocks: usize,
    //fns: HashMap<String, CoverageFunction, FxBuildHasher>,
}

impl CoverageFile {
    pub fn new(cov: FileCoverage) -> Self {
        let mut covered_blocks = 0;
        let mut total_blocks = 0;
        // let mut functions = HashMap::with_hasher(FxBuildHasher::default());
        for (fn_name, function) in cov.fns {
            covered_blocks += function.executed_blocks;
            total_blocks += function.total_blocks;

            /*
            functions.insert(fn_name, CoverageFunction {
                covered_blocks: function.executed_blocks,
                total_blocks: function.total_blocks,
            });
            */
        }

        Self {
            covered_blocks,
            total_blocks,
            // fns: functions,
        }
    }
}

/*
#[derive(Deserialize, Serialize)]
struct CoverageFunction {
    covered_blocks: usize,
    total_blocks: usize,
}
*/
