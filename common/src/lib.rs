use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub mod reader;
pub mod prelude;

#[derive(Debug, Deserialize, Serialize)]
pub struct ProgCoverage {
    pub cwd: String,
    pub files: HashMap<String, FileCoverage, fxhash::FxBuildHasher>,
}

impl ProgCoverage {
    pub fn merge(&mut self, other: ProgCoverage) -> Result<(), String> {
        for (filename, file) in other.files.into_iter() {
            match self.files.entry(filename) {
                std::collections::hash_map::Entry::Occupied(mut old_file) => {
                    if self.cwd != other.cwd {
                        return Err(format!("cwd mismatch in program coverage during merge: `{}` vs `{}`", self.cwd, other.cwd))
                    }

                    let old_fns = &mut old_file.get_mut().fns;
                    for (function_name, function) in file.fns.into_iter() {
                        match old_fns.entry(function_name) {
                            std::collections::hash_map::Entry::Occupied(old_fn) => {
                                let function_name = old_fn.key().clone();
                                return Err(format!("duplicate function coverage found for {} in {}", function_name, old_file.key()))
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
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
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
