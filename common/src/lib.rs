use std::collections::HashMap;
use std::cmp;

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
                            std::collections::hash_map::Entry::Occupied(mut old_entry) => {
                                // Based on experimentation, these are always the same in line count, start line, total blocks, etc.

                                if old_entry.get().total_blocks != function.total_blocks {
                                    log::warn!("discarding duplicate function that had differing total_blocks: {}", old_entry.key());
                                    continue
                                }

                                if old_entry.get().lines.len() != function.lines.len() {
                                    log::warn!("discarding duplicate function that had differing total lines: {}", old_entry.key());
                                    continue
                                }

                                let old_function = old_entry.get_mut();
                                
                                // The new total executed blocks is the set addition of the two block counts
                                let mut new_executed_blocks = 0;

                                for (old_block, new_block) in old_function.blocks.iter_mut().zip(function.blocks.iter()) {
                                    // TODO: should we sum the total executions here, or take the max of either?
                                    // Why are there multiple files in the first place?
                                    old_block.executions = cmp::max(old_block.executions, new_block.executions);
                                    new_executed_blocks += if old_block.executions > 0 { 1 } else { 0 };
                                }
                                old_function.executed_blocks = new_executed_blocks;

                                for (old_line, new_line) in old_function.lines.iter_mut().zip(function.lines.iter()) {
                                    // TODO: same here as in prior for loop--sum, or max?
                                    old_line.exec_count = cmp::max(old_line.exec_count, new_line.exec_count);
                                }
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
