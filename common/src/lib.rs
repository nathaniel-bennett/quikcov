use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub mod reader;
pub mod prelude;

#[derive(Debug, Deserialize, Serialize)]
pub struct ProgCoverage {
    pub cwd: Option<String>,
    pub files: HashMap<String, FileCoverage, fxhash::FxBuildHasher>,
}

impl ProgCoverage {
    pub fn merge(&mut self, other: ProgCoverage) -> Result<(), String> {
        for (filename, file) in other.files.into_iter() {
            match self.files.entry(filename) {
                std::collections::hash_map::Entry::Occupied(mut old_file) => {
                    if self.cwd != other.cwd {
                        return Err(format!("cwd mismatch in program coverage during merge: `{:?}` vs `{:?}`", self.cwd, other.cwd))
                    }

                    let old_fns = &mut old_file.get_mut().fns;
                    for (function_name, function) in file.fns.into_iter() {

                        match old_fns.entry(function_name) {
                            std::collections::hash_map::Entry::Occupied(mut old_fn) => {
                                let function_name = old_fn.key().clone();
                                log::info!("multiple function coverage objects for {}", function_name);
                                
                                if old_fn.get().total_blocks == function.total_blocks {
                                    if old_fn.get().start_line != function.start_line {
                                        log::warn!("start lines differed for {}", function_name);
                                    }

                                    if old_fn.get().lines.len() != function.lines.len() {
                                        log::warn!("number of lines differed for {}", function_name);
                                    }
                                    old_fn.get_mut().executed_blocks = std::cmp::max(old_fn.get().executed_blocks, function.executed_blocks);
                                } else {
                                    log::warn!("duplicate function {} had differing block counts", function_name);
                                }

                                //old_fn.get_mut().executed_blocks += function.executed_blocks;
                                //old_fn.insert(function);

                                // println!("Warning: duplicate function coverage for {} in file {}", function_name, filename);
                            },
                            std::collections::hash_map::Entry::Vacant(vacancy) => {
                                vacancy.insert(function);
                            },
                        }
                    }
                },
                std::collections::hash_map::Entry::Vacant(vacancy) => {
                    vacancy.insert(file);
                },
            }
        }

        Ok(())
    } 
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FileCoverage {
    pub fns: HashMap<String, FnCoverage, fxhash::FxBuildHasher>,
//    /// Lines unassociated with any function in the file
//    pub unassociated_lines: Vec<LineCoverage>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FnCoverage {
    pub start_line: u32,
    pub start_col: Option<u32>,
    pub end_line: Option<u32>,
    pub end_col: Option<u32>,
//    pub exec_count: u32,
    pub executed_blocks: usize,
    pub total_blocks: usize,
    pub lines: Vec<LineCoverage>,
    pub blocks: Vec<BlockCoverage>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LineCoverage {
    pub lineno: u32,
    pub exec_count: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BlockCoverage {
    pub executions: u64,
}
