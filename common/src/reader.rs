use std::collections::{HashMap, HashSet};
use std::ffi::CStr;

use fxhash::FxBuildHasher;

use crate::{FileCoverage, FnCoverage, LineCoverage, BlockCoverage, ProgCoverage};

const GCOV_ARC_ON_TREE: u32 = 1 << 0;
const GCOV_ARC_FAKE: u32 = 1 << 1;
//const GCOV_ARC_FALLTHROUGH: u32 = 1 << 2;
const GCOV_TAG_FUNCTION: u32 = 0x0100_0000;
const GCOV_TAG_BLOCKS: u32 = 0x0141_0000;
const GCOV_TAG_ARCS: u32 = 0x0143_0000;
const GCOV_TAG_CONDS: u32 = 0x0147_0000;
const GCOV_TAG_PATHS: u32 = 0x0149_0000;
const GCOV_TAG_LINES: u32 = 0x0145_0000;
const GCOV_TAG_COUNTER_ARCS: u32 = 0x01a1_0000;
const GCOV_TAG_OBJECT_SUMMARY: u32 = 0xa100_0000;
const GCOV_TAG_PROGRAM_SUMMARY: u32 = 0xa300_0000;
const GCOV_TAG_AFDO_FILE_NAMES: u32 = 0xaa00_0000;
const GCOV_TAG_AFDO_FUNCTION: u32 = 0xac00_0000;
const GCOV_TAG_AFDO_WORKING_SET: u32 = 0xaf00_0000;

// We don't currently support GCC < 8

enum Magic {
    Gcda,
    Gcno,
}

#[derive(Debug)]
pub enum Error {
    Checksum,
    Endianness,
    Length,
    Utf8,
    IncompleteFile,
    InsufficientBytes,
    TrailingBytes,
    Value(&'static str),
    Version,
    VersionMismatch,
}

#[derive(Clone)]
pub struct Gcno {
    pub version: u32,
    pub chksum: u32,
    pub cwd: Option<String>,
    pub ident_fn_idx: HashMap<u32, usize, FxBuildHasher>,
    pub functions: Vec<GcnoFunction>,
}

#[derive(Clone)]
pub struct GcnoFunction {
    pub ident: u32,
    pub line_chksum: u32,
    pub cfg_chksum: Option<u32>,
    pub name: String,
    pub artificial: Option<u32>,
    pub file_name: String,
    pub start_line: u32,
    pub start_col: Option<u32>,
    pub end_line: Option<u32>,
    pub end_col: Option<u32>,
    pub lines: HashMap<u32, u64>,
    pub blocks: Vec<GcnoBlock>,
    pub edges: Vec<GcnoEdge>,
    pub real_edge_cnt: usize,
    pub executed: bool,
}

#[derive(Clone)]
pub struct GcnoEdge {
    pub src: usize,
    pub dst: usize,
    pub flags: u32,
    pub counter: u64,
    pub cycles: u64,
}

#[derive(Clone)]
pub struct GcnoBlock {
    pub block_id: usize,
    pub src: Vec<usize>,
    pub dst: Vec<usize>,
    pub lines: Vec<u32>,
    pub line_max: u32,
    pub counter: u64,
}

impl GcnoBlock {
    #[inline]
    pub fn new(block_id: usize) -> Self {
        Self {
            block_id,
            src: Vec::new(),
            dst: Vec::new(),
            lines: Vec::new(),
            line_max: 0,
            counter: 0, 
        }
    }
}

impl Gcno {
    pub fn from_slice(input: &[u8]) -> Result<Self, Error> {
        let mut reader = ByteReader::new(input);

        // This parsing is all taken from the `read_graph_file()` function contained in `gcc/gcov.cc` in the gcc github project:
        // `https://github.com/gcc-mirror/gcc/blob/master/gcc/gcov.cc#L2202`

        let Magic::Gcno = reader.get_magic_number()? else {
            log::error!("wrong file magic number encountered while decoding .gcno (expected .gcno, got .gcda");
            return Err(Error::Value(".gcda magic number where .gcno was expected"))
        };

        let version = reader.get_version()?;
        log::debug!(".gcno file version {} detected", version);


        // This gets added in commit 72e0c742bd01f8e7e6dcca64042b9ad7e75979de, which was subsequently released in GCC 11.3
        let _bbg_stamp = if version >= 113 { Some(reader.get_u32()?) } else { None };
        let chksum = reader.get_u32()?;
        
        let cwd = if version >= 90 { Some(reader.get_string(version)?) } else { None };
        if let Some(cwd) = &cwd {
            log::debug!("cwd={}", cwd);
        }

        // bbg_supports_has_unexecuted_blocks
        let has_unexecuted_blocks = if version >= 80 { Some(reader.get_u32()?) } else { None };
        log::debug!("has_unexecuted_blocks={:?}", has_unexecuted_blocks);

        let mut ident_fn_idx = HashMap::with_hasher(FxBuildHasher::default());
        let mut functions = Vec::new();

        while !reader.is_empty() {
            let tag = reader.get_u32()?;

            match tag {
                0 => if !reader.is_empty() {
                    log::error!("null tag reached while reader had bytes remaining in .gcno file");
                    return Err(Error::TrailingBytes)
                } else {
                    break
                }
                GCOV_TAG_FUNCTION => {
                    log::trace!("parsing gcno function element");
                    let function = Self::read_function(&mut reader, version)?;
                    let idx = functions.len();
                    ident_fn_idx.insert(function.ident, idx);
                    functions.push(function);
                }
                GCOV_TAG_BLOCKS => {
                    log::trace!("parsing gcno blocks element");
                    let Some(function) = functions.last_mut() else {
                        continue
                    };
                    Self::read_blocks(&mut reader, function, version)?;
                }
                GCOV_TAG_ARCS => {
                    log::trace!("parsing gcno arcs element");
                    let Some(function) = functions.last_mut() else {
                        continue
                    };
                    
                    Self::read_arcs(&mut reader, function)?;
                }
                GCOV_TAG_LINES => {
                    log::trace!("parsing gcno lines element");
                    let Some(function) = functions.last_mut() else {
                        continue
                    };
                    Self::read_lines(&mut reader, function, version)?;
                }
                elem_tag => {
                    log::warn!("unrecognized element tag {} found in gcno file", elem_tag);
                    let mut length = reader.get_u32()? as usize;
                    if version < 130 {
                        length = length * 4;
                    }
                    log::debug!("unrecognized element tag {} had length {}", elem_tag, length);
                    reader.discard(length)?;
                }
            }
        }

        Ok(Self {
            version,
            chksum,
            cwd,
            ident_fn_idx,
            functions,
        })
    }

    fn read_function(reader: &mut ByteReader<'_>, version: u32) -> Result<GcnoFunction, Error> {
        let mut length = reader.get_u32()? as usize;
        if version < 130 {
            length = length * 4;
        }

        let Some(remainder) = reader.remainder().get(..length) else {
            log::error!("insufficient bytes to satisfy length {} requirement for function", length);
            return Err(Error::InsufficientBytes)
        };
        reader.discard(length)?;
        let mut reader = ByteReader::new(remainder);

        let function = GcnoFunction {
            ident: reader.get_u32()?,
            line_chksum: reader.get_u32()?,
            cfg_chksum: if version >= 47 { Some(reader.get_u32()?) } else { None },
            name: reader.get_string(version)?,
            artificial: if version >= 80 { Some(reader.get_u32()?) } else { None },
            file_name: reader.get_string(version)?,
            start_line: reader.get_u32()?,
            start_col: if version >= 80 { Some(reader.get_u32()?) } else { None },
            end_line: if version >= 80 { Some(reader.get_u32()?) } else { None },
            end_col: if version >= 80 { Some(reader.get_u32()?) } else { None },
            real_edge_cnt: 0,
            edges: Vec::new(),
            blocks: Vec::new(),
            lines: HashMap::new(),
            executed: false,
        };

        reader.finish()?;
        Ok(function)
    }

    fn read_blocks(reader: &mut ByteReader<'_>, function: &mut GcnoFunction, version: u32) -> Result<(), Error> {
        let length = reader.get_u32()? as usize;
        
        if version >= 80 {
            let length = reader.get_u32()? as usize; // No, this is not a bug. There is an addition length field.
            for idx in 0..length {
                function.blocks.push(GcnoBlock::new(idx));
            }
        } else {
            for idx in 0..length {
                let _flags = reader.get_u32()?;
                function.blocks.push(GcnoBlock::new(idx));
            }
        }

        Ok(())
    }

    fn read_arcs(reader: &mut ByteReader<'_>, function: &mut GcnoFunction) -> Result<(), Error> {
        let length = reader.get_u32()? as usize;

        // TODO: didn't used to have / 4--version change?
        let count = (((length / 4).checked_sub(1).ok_or(Error::InsufficientBytes)?) / 2) as usize;
        let block_id = reader.get_u32()? as usize;

        let Some(block) = function.blocks.get_mut(block_id) else {
            return Err(Error::Value("block id exceeded total block count in arcs"))
        };

        block.dst.reserve(count);
        for _ in 0..count {
            let dst_block_id = reader.get_u32()? as usize;
            let flags = reader.get_u32()?;
            let edges_cnt = function.edges.len();

            function.edges.push(GcnoEdge {
                src: block_id,
                dst: dst_block_id,
                flags,
                counter: 0,
                cycles: 0,
            });

            let i = match block.dst.binary_search_by(|x| function.edges.get(*x).map(|d| d.dst.cmp(&dst_block_id)).unwrap_or(std::cmp::Ordering::Less)) {
                Ok(idx) => idx,
                Err(idx) => idx,
            };

            block.dst.insert(i, edges_cnt);
            block.src.push(edges_cnt);
            if (flags & GCOV_ARC_ON_TREE) == 0 {
                function.real_edge_cnt += 1;
            }
        }

        Ok(())
    }

    fn read_lines(reader: &mut ByteReader<'_>, function: &mut GcnoFunction, version: u32) -> Result<(), Error> {
        let _length = reader.get_u32()? as usize;
        let block_id = reader.get_u32()? as usize;
        
        let Some(block) = function.blocks.get_mut(block_id) else {
            return Err(Error::Value("block id exceeded total block count in lines"))
        };

        let mut line_in_file = false;

        loop {
            let line = reader.get_u32()?;
            if line == 0 {
                let filename = reader.get_string(version)?;
                if filename.is_empty() {
                    break
                } else {
                    line_in_file = filename == function.file_name;
                    continue // Line originates from another file
                    // FIXME: implement this
                }
            }

            if !line_in_file || (version >= 80 && (line < function.start_line || line > function.end_line.ok_or(Error::Value("missing end line despite version indicating presence"))?)) {
                continue
            }

            function.lines.insert(line, 0);
            block.line_max = std::cmp::max(block.line_max, line);
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct FileCovBuilder {
    gcno: Gcno,
    current_fn_idx: Option<usize>,
    run_counts: u32,
    program_counts: u32,
}

impl FileCovBuilder {
    pub fn new(gcno: Gcno) -> Self {
        Self {
            gcno,
            current_fn_idx: None,
            run_counts: 0,
            program_counts: 0,
        }
    }

    pub fn build(mut self) -> Result<ProgCoverage, Error> {
        self.account_on_tree_arcs()?;
        self.account_lines()?;

        //let cwd = self.gcno.cwd.ok_or(Error::Value("file missing cwd"))?;
        let mut files = HashMap::with_hasher(FxBuildHasher::default());

        for function in self.gcno.functions {
            let lines = function.lines.iter().map(|(&lineno, &exec_count)| LineCoverage {
                lineno,
                exec_count,
            }).collect();

            let blocks = function.blocks.iter().map(|block| BlockCoverage {
                executions: block.counter,
            }).collect();

            let fn_coverage = FnCoverage {
                start_line: function.start_line,
                start_col: function.start_col,
                end_line: function.end_line,
                end_col: function.end_col,
                executed_blocks: function.blocks.iter().filter(|b| b.counter > 0).count(),
                total_blocks: function.blocks.len(),
                blocks,
                lines,
            };

            let file = files.entry(function.file_name).or_insert(FileCoverage {
                fns: HashMap::with_hasher(FxBuildHasher::default()),
            });

            let None = file.fns.insert(function.name, fn_coverage) else {
                return Err(Error::Value("collision in function names for a given file"))
            };
        }

        Ok(ProgCoverage {
            cwd: self.gcno.cwd,
            files,
        })
    }

    fn account_lines(&mut self) -> Result<(), Error> {
        for function in self.gcno.functions.iter_mut() {
            function.executed = function.edges.first().map(|e| e.counter > 0).unwrap_or(false);
            if !function.executed {
                for block in function.blocks.iter() {
                    for line in block.lines.iter() {
                        function.lines.entry(*line).or_insert(0); // Add a line with 0 executions
                    }
                }
            } else {
                let mut line_counts = HashMap::with_capacity_and_hasher(function.blocks.len(), FxBuildHasher::default());
                
                for block in function.blocks.iter() {
                    for line in block.lines.iter() {
                        *line_counts.entry(*line).or_insert(0) += block.counter;
                        // FIXME: this is a simplistic and likely wrong measure. See grcov for more precise measurement
                    }
                }

                for (line_number, line_count) in line_counts {
                    function.lines.insert(line_number, line_count);
                }
            }
        }

        Ok(())
    }

    fn account_on_tree_arcs(&mut self) -> Result<(), Error> {
        // TODO: verify this is working correctly

        for function in self.gcno.functions.iter_mut() {
            if function.blocks.len() < 2 {
                continue
            }

            let src_id = 0;
            let sink_id = if self.gcno.version < 48 {
                function.blocks.len() - 1
            } else {
                1
            };
            let edges_cnt = function.edges.len();
            function.edges.push(GcnoEdge {
                src: sink_id,
                dst: src_id,
                flags: GCOV_ARC_ON_TREE,
                counter: 0,
                cycles: 0,
            });

            let sink_block = function.blocks.get_mut(sink_id).ok_or(Error::Value("internal: error indexing sink_id while accounting for on-tree arcs"))?;

            let i = match sink_block.dst.binary_search_by(|x| function.edges.get(*x).map(|d| d.dst.cmp(&src_id)).unwrap_or(std::cmp::Ordering::Less)) {
                Ok(idx) => idx,
                Err(idx) => idx,
            };

            sink_block.dst.insert(i, edges_cnt);

            let src_block = function.blocks.get_mut(src_id).ok_or(Error::Value("internal: error indexing src_id while accounting for on-tree arcs"))?;
            src_block.src.push(edges_cnt);

            let mut visited = HashSet::default();
            for block_id in 0..function.blocks.len() {
                Self::propagate_counts(&mut function.blocks, &mut function.edges, block_id, None, &mut visited);
            }

            for edge in function.edges.iter().rev() {
                if (edge.flags & GCOV_ARC_ON_TREE) != 0 {
                    function.blocks.get_mut(edge.src).ok_or(Error::Value("internal: failed to index block based on edge id"))?.counter += edge.counter;
                }
            }
        }

        Ok(())
    }

    // Note: taken from `grcov` (MPL 2.0)
    fn propagate_counts(
        blocks: &Vec<GcnoBlock>,
        edges: &mut Vec<GcnoEdge>,
        block_no: usize,
        pred_arc: Option<usize>,
        visited: &mut HashSet<usize, FxBuildHasher>,
    ) -> u64 {
        // For each basic block, the sum of incoming edge counts equals the sum of
        // outgoing edge counts by Kirchoff's circuit law. If the unmeasured arcs form a
        // spanning tree, the count for each unmeasured arc (GCOV_ARC_ON_TREE) can be
        // uniquely identified.

        // Prevent infinite recursion
        if !visited.insert(block_no) {
            return 0;
        }
        let mut positive_excess = 0;
        let mut negative_excess = 0;
        let block = &blocks[block_no];
        for edge_id in block.src.iter() {
            if pred_arc.map_or(true, |x| *edge_id != x) {
                let edge = &edges[*edge_id];
                positive_excess += if (edge.flags & GCOV_ARC_ON_TREE) != 0 {
                    let source = edge.src;
                    Self::propagate_counts(blocks, edges, source, Some(*edge_id), visited)
                } else {
                    edge.counter
                };
            }
        }
        for edge_id in block.dst.iter() {
            if pred_arc.map_or(true, |x| *edge_id != x) {
                let edge = &edges[*edge_id];
                negative_excess += if (edge.flags & GCOV_ARC_ON_TREE) != 0 {
                    let destination = edge.dst;
                    Self::propagate_counts(blocks, edges, destination, Some(*edge_id), visited)
                } else {
                    edge.counter
                };
            }
        }
        let excess = if positive_excess >= negative_excess {
            positive_excess - negative_excess
        } else {
            negative_excess - positive_excess
        };
        if let Some(id) = pred_arc {
            let edge = &mut edges[id];
            edge.counter = excess;
        }
        excess
    }

    pub fn add_gcda(&mut self, input: &[u8]) -> Result<(), Error> {
        let mut reader = ByteReader::new(input);

        let Magic::Gcda = reader.get_magic_number()? else {
            return Err(Error::Value("file type gcda needed but gcno found"))
        };
        let version = reader.get_version()?;
        let chksum = reader.get_u32()?;

        if version != self.gcno.version {
            return Err(Error::VersionMismatch)
        }

        if chksum != self.gcno.chksum {
            return Err(Error::Checksum)
        }

        while !reader.is_empty() {
            let tag = reader.get_u32()?;
            match tag {
                GCOV_TAG_FUNCTION => self.read_function(&mut reader)?,
                GCOV_TAG_COUNTER_ARCS => self.read_arcs(&mut reader)?,
                GCOV_TAG_OBJECT_SUMMARY => {
                    log::trace!("parsing gcda Object Summary element");
                    let mut length = reader.get_u32()? as usize;
                    if version < 130 {
                        length = length * 4;
                    }

                    if length == 0 {
                        log::warn!("Object Summary element contained no bytes");
                        continue
                    }

                    let mut summary_reader = ByteReader::new(reader.get_bytes(length)?);
                    let run_counts = summary_reader.get_u32()?;
                    summary_reader.get_u32()?; // skip unused value
                    self.run_counts += if length == 9 { summary_reader.get_u32()? } else { run_counts };

                    if !summary_reader.is_empty() {
                        log::trace!("Object Summary element contained excess unread bytes");
                    }

                    // TODO: drain excess bytes
                }
                GCOV_TAG_PROGRAM_SUMMARY => {
                    log::trace!("parsing gcda program summary element");
                    let mut length = reader.get_u32()? as usize;
                    if version < 130 {
                        length = length * 4;
                    }

                    if length == 0 {
                        log::warn!("Program Summary element contained no bytes");
                        continue
                    }

                    let mut summary_reader = ByteReader::new(reader.get_bytes(length)?);
                    summary_reader.get_u32()?; // skip unused value
                    summary_reader.get_u32()?; // skip unused value
                    self.run_counts += summary_reader.get_u32()?;
                    self.program_counts += 1;

                    if !summary_reader.is_empty() {
                        log::trace!("Program Summary element contained excess unread bytes");
                    }
                }
                0 if reader.is_empty() => break,
                0 => {
                    log::error!("element tag 0 reached yet .gcda file had trailing bytes");
                    return Err(Error::TrailingBytes)
                }
                elem_tag => {
                    let mut length = reader.get_u32()? as usize;
                    if version < 130 {
                        length = length * 4;
                    }
                    log::warn!("unrecognized element tag {}  of length {} found in gcda file", elem_tag, length);
                    reader.discard(length)?;
                }
            }
        }

        Ok(())
    }

    fn read_function(&mut self, reader: &mut ByteReader<'_>) -> Result<(), Error> {
        log::trace!("parsing gcda function element");
        let length = reader.get_u32()? as usize;
        if length == 0 {
            log::warn!("empty function element (length = 0)");
            return Ok(())
        }

        if length != 3 {
            return Err(Error::Length)
        }

        let function_id = reader.get_u32()?;
        let line_chksum = reader.get_u32()?;
        let cfg_chksum = if self.gcno.version >= 47 { Some(reader.get_u32()?) } else { None };

        let Some(function_idx) = self.gcno.ident_fn_idx.get(&function_id) else {
            return Err(Error::Value("invalid function identifier--does not map to any function in corresponding gcno file"))
        };

        let Some(function) = self.gcno.functions.get_mut(*function_idx) else {
            return Err(Error::Value("internal: invalid function index for function identifier while parsing functions"))
        };

        if line_chksum != function.line_chksum || cfg_chksum != function.cfg_chksum {
            return Err(Error::Checksum)
        }

        self.current_fn_idx = Some(*function_idx);

        Ok(())
    }

    fn read_arcs(&mut self, reader: &mut ByteReader<'_>) -> Result<(), Error> {
        log::trace!("parsing gcda arcs element");
        let length = reader.get_u32()? as usize;

        let Some(function_idx) = self.current_fn_idx else {
            return Ok(())
        };

        let Some(function) = self.gcno.functions.get_mut(function_idx) else {
            return Err(Error::Value("internal: invalid function index for function identifier while parsing arcs"))
        };


        if function.real_edge_cnt != length / 2 {
            return Err(Error::Value("incorrect number of edges found for function in gcda"))
        }

        for edge in function.edges.iter_mut() {
            if (edge.flags & GCOV_ARC_ON_TREE) != 0 {
                continue // ignore
            }

            let block = function.blocks.get_mut(edge.src).ok_or(Error::Value("edge source id exceeded maximum block id"))?;
            let counter = reader.get_u64()?;
            block.counter += counter;
            edge.counter += counter;
        }
        

        Ok(())
    }
}


struct ByteReader<'a> {
    slice: &'a [u8],
}

impl<'a> ByteReader<'a> {
    #[inline]
    pub fn new(input: &'a [u8]) -> Self {
        Self { slice: input }
    }

    /*
    #[inline]
    pub fn len(&self) -> usize {
        self.slice.len()
    }
    */

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.slice.is_empty()
    }

    #[inline]
    pub fn discard(&mut self, amount: usize) -> Result<(), Error> {
        self.slice = self.slice.get(amount..).ok_or(Error::InsufficientBytes)?;
        Ok(())
    }

    #[inline]
    pub fn finish(self) -> Result<(), Error> {
        if self.is_empty() {
            Ok(())
        } else {
            log::error!(".gcno file had unused/unrecognized bytes at end of element");
            Err(Error::TrailingBytes)
        }
    }

    #[inline]
    pub fn remainder(&self) -> &'a [u8] {
        self.slice
    }

    #[inline]
    pub fn get_magic_number(&mut self) -> Result<Magic, Error> {
        match &self.get_u32()?.to_be_bytes() { // Magic number
            b"gcda" => Ok(Magic::Gcda),
            b"gcno" => Ok(Magic::Gcno),
            b"adcg" | b"oncg" => Err(Error::Endianness),
            _ => Err(Error::Value("invalid magic number at start of file (should be gcno, or oncg for little endian systems)")),
        }
    }

    #[inline]
    pub fn get_string(&mut self, version: u32) -> Result<String, Error> {
        // This changed in commit 23eb66d1d46a34cb28c4acbdf8a1deb80a7c5a05, which was included in version 13.0

        let mut length = self.get_u32()? as usize;
        if version < 130 {
            length = length * 4;
        }

        if length == 0 {
            Ok(String::default())
        } else {
            let bytes = self.get_bytes(length)?;

            let Ok(c_str) = CStr::from_bytes_until_nul(bytes) else {
                log::error!("String missing null-terminating byte");
                return Err(Error::Value("missing null-terminating byte in string"))
            };
            Ok(c_str.to_str().map_err(|_| Error::Utf8)?.to_string())
        }
    }

    #[inline]
    pub fn get_u64(&mut self) -> Result<u64, Error> {
        let low = self.get_u32()?;
        let high = self.get_u32()?;
        Ok(u64::from(high) << 32 | u64::from(low))
    }

    #[inline]
    fn get_version(&mut self) -> Result<u32, Error> {
        // FIXME: assumes little endianness
        let [b0, b1, b2, b3] = self.get_array::<4>()?;

        if b0 != b'*' {
            return Err(Error::Version)
        }


        if let Some(n3) =  b3.checked_sub(b'A') {
            let (Some(n2), Some(n1)) = (b2.checked_sub(b'0'), b1.checked_sub(b'0')) else {
                return Err(Error::Version)
            };

            Ok(100 * u32::from(n3) + 10 * u32::from(n2) + u32::from(n1))
        } else {
            let (Some(n1), Some(n3)) = (b1.checked_sub(b'0'), b3.checked_sub(b'0')) else {
                return Err(Error::Version)
            };

            Ok(10 * u32::from(n3) + u32::from(n1))
        }
    }

    #[inline]
    fn get_bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let bytes;
        (bytes, self.slice) = match (self.slice.get(..len), self.slice.get(len..)) {
            (Some(a), Some(b)) => (a, b),
            _ => return Err(Error::InsufficientBytes),
        };

        Ok(bytes)
    }

    #[inline]
    fn get_u32(&mut self) -> Result<u32, Error> {
        let arr = self.get_array()?;
        Ok(u32::from_ne_bytes(arr))
    }

    #[inline]
    fn get_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        match (self.slice.get(..N), self.slice.get(N..)) {
            (Some(s), Some(rem)) => {
                let arr = s.try_into().map_err(|_| Error::Value("internal: could not convert data to fixed-size array"))?;
                self.slice = rem;
                Ok(arr)
            }
            _ => Err(Error::InsufficientBytes),
        }
    }
}


