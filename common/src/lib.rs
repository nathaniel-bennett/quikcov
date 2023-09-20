use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub mod reader;
pub mod prelude;

#[derive(Debug, Deserialize, Serialize)]
pub struct ProgCoverage {
    pub files: HashMap<String, FileCoverage, fxhash::FxBuildHasher>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FileCoverage {
    pub cwd: String,
    pub fns: HashMap<FnIndex, FnCoverage, fxhash::FxBuildHasher>,
//    /// Lines unassociated with any function in the file
//    pub unassociated_lines: Vec<LineCoverage>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct FnIndex {
    pub start_line: u32,
    pub start_col: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FnCoverage {
    pub name: String,
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
