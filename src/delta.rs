use std::{
    collections::{HashMap, VecDeque},
    io::{BufReader, Cursor, Read, Seek, SeekFrom, Write},
};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub const MAX_LITERAL: usize = 1024 * 1024;
pub const SIGNATURE_BUDGET: usize = 512 * 1024 * 1024;
pub const WIRE_SIGNATURE_BUDGET: usize = 4 * 1024 * 1024;
pub const MAX_BLOCK_SIZE: usize = 8 * 1024 * 1024;
const SIGNATURE_BYTES: usize = 40;
// A malicious peer can deliberately manufacture many blocks with one weak
// checksum.  Skipping an overfull bucket preserves correctness (the source is
// emitted literally) while keeping candidate verification bounded.
const MAX_WEAK_CANDIDATES: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    pub block_index: u64,
    pub length: u32,
    pub weak: u32,
    pub strong: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Instruction {
    Copy { first_block: u64, block_count: u32 },
    Literal(#[serde(with = "serde_bytes")] Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Trailer {
    pub length: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delta {
    pub block_size: usize,
    pub instructions: Vec<Instruction>,
    pub trailer: Trailer,
}

#[must_use]
pub fn choose_block_size(file_size: u64, budget: usize) -> usize {
    if file_size == 0 {
        return 4096;
    }
    let sqrt = (file_size as f64).sqrt().ceil() as u64;
    let max_blocks = (budget / SIGNATURE_BYTES).max(1) as u64;
    let budget_size = file_size.div_ceil(max_blocks);
    usize::try_from(sqrt.max(budget_size).max(4096)).unwrap_or(usize::MAX)
}

pub fn signatures(basis: &[u8], block_size: usize) -> Result<Vec<Signature>> {
    signatures_with_budget(basis, block_size, SIGNATURE_BUDGET)
}

pub fn signatures_with_budget(
    basis: &[u8],
    block_size: usize,
    budget: usize,
) -> Result<Vec<Signature>> {
    validate_block_size(block_size)?;
    let block_count = basis.len().div_ceil(block_size);
    if block_count.saturating_mul(SIGNATURE_BYTES) > budget {
        return Err(Error::Protocol(
            "basis signatures exceed memory budget".into(),
        ));
    }
    Ok(basis
        .chunks(block_size)
        .enumerate()
        .map(|(index, block)| Signature {
            block_index: index as u64,
            length: block.len() as u32,
            weak: weak_checksum(block),
            strong: strong16(block),
        })
        .collect())
}

pub fn signatures_from_reader<R: Read>(
    mut basis: R,
    block_size: usize,
    budget: usize,
) -> Result<Vec<Signature>> {
    validate_block_size(block_size)?;
    let max_signatures = budget / SIGNATURE_BYTES;
    let mut signatures = Vec::new();
    let mut block = vec![0u8; block_size];
    loop {
        let mut used = 0usize;
        while used < block.len() {
            let count = basis
                .read(&mut block[used..])
                .map_err(|error| Error::io(None, error))?;
            if count == 0 {
                break;
            }
            used += count;
        }
        if used == 0 {
            break;
        }
        if signatures.len() >= max_signatures {
            return Err(Error::Protocol(
                "basis signatures exceed memory budget".into(),
            ));
        }
        signatures.push(Signature {
            block_index: signatures.len() as u64,
            length: u32::try_from(used)
                .map_err(|_| Error::Protocol("delta block is too large".into()))?,
            weak: weak_checksum(&block[..used]),
            strong: strong16(&block[..used]),
        });
        if used < block.len() {
            break;
        }
    }
    Ok(signatures)
}

pub fn generate(source: &[u8], basis_signatures: &[Signature], block_size: usize) -> Result<Delta> {
    let mut instructions = Vec::new();
    let trailer = generate_stream(
        Cursor::new(source),
        basis_signatures,
        block_size,
        |instruction| {
            instructions.push(instruction);
            Ok(())
        },
    )?;
    Ok(Delta {
        block_size,
        instructions,
        trailer,
    })
}

pub fn generate_stream<R: Read, F: FnMut(Instruction) -> Result<()>>(
    source: R,
    basis_signatures: &[Signature],
    block_size: usize,
    mut emit: F,
) -> Result<Trailer> {
    validate_block_size(block_size)?;
    for signature in basis_signatures {
        if signature.length == 0 || signature.length as usize > block_size {
            return Err(Error::Protocol("invalid basis signature length".into()));
        }
    }
    if basis_signatures.is_empty() {
        let mut reader = BufReader::new(source);
        let mut buffer = vec![0u8; MAX_LITERAL];
        let mut hasher = blake3::Hasher::new();
        let mut length = 0u64;
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|error| Error::io(None, error))?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            length = length
                .checked_add(count as u64)
                .ok_or_else(|| Error::Protocol("source length overflow".into()))?;
            emit(Instruction::Literal(buffer[..count].to_vec()))?;
        }
        return Ok(Trailer {
            length,
            digest: *hasher.finalize().as_bytes(),
        });
    }
    let mut by_weak: HashMap<u32, Vec<&Signature>> = HashMap::new();
    for signature in basis_signatures {
        let candidates = by_weak.entry(signature.weak).or_default();
        if candidates.len() <= MAX_WEAK_CANDIDATES {
            candidates.push(signature);
        }
    }
    let mut emitter = InstructionEmitter::new(emit);
    let mut hasher = blake3::Hasher::new();
    let mut length = 0u64;
    let mut reader = BufReader::new(source);
    let mut window = VecDeque::with_capacity(block_size);
    let mut eof = fill_window(&mut reader, &mut window, block_size)?;
    let mut weak = WeakState::new(&window);
    while !window.is_empty() {
        let matched = by_weak
            .get(&weak.value())
            .filter(|candidates| candidates.len() <= MAX_WEAK_CANDIDATES)
            .and_then(|candidates| {
                let contiguous = window.make_contiguous();
                let digest = strong16(contiguous);
                candidates
                    .iter()
                    .find(|candidate| {
                        usize::try_from(candidate.length).ok() == Some(contiguous.len())
                            && candidate.strong == digest
                    })
                    .copied()
            });
        if let Some(signature) = matched {
            let bytes = window.make_contiguous();
            hasher.update(bytes);
            length = length
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| Error::Protocol("source length overflow".into()))?;
            emitter.push_copy(signature.block_index)?;
            window.clear();
            eof = fill_window(&mut reader, &mut window, block_size)?;
            weak = WeakState::new(&window);
        } else {
            let previous_len = window.len();
            let byte = window.pop_front().expect("nonempty rolling window");
            hasher.update(&[byte]);
            length = length
                .checked_add(1)
                .ok_or_else(|| Error::Protocol("source length overflow".into()))?;
            emitter.push_literal(byte)?;
            if !eof {
                let mut incoming = [0u8; 1];
                let count = reader
                    .read(&mut incoming)
                    .map_err(|error| Error::io(None, error))?;
                if count == 0 {
                    eof = true;
                    weak = WeakState::new(&window);
                } else {
                    window.push_back(incoming[0]);
                    if previous_len == block_size {
                        weak.roll(byte, incoming[0]);
                    } else {
                        weak = WeakState::new(&window);
                    }
                }
            } else {
                weak = WeakState::new(&window);
            }
        }
    }
    emitter.finish()?;
    Ok(Trailer {
        length,
        digest: *hasher.finalize().as_bytes(),
    })
}

pub fn apply(basis: &[u8], delta: &Delta, output_limit: u64) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    apply_stream(
        Cursor::new(basis),
        basis.len() as u64,
        delta.block_size,
        &delta.instructions,
        delta.trailer,
        output_limit,
        &mut output,
    )?;
    Ok(output)
}

pub fn apply_stream<B: Read + Seek, W: Write>(
    basis: B,
    basis_length: u64,
    block_size: usize,
    instructions: &[Instruction],
    trailer: Trailer,
    output_limit: u64,
    output: W,
) -> Result<()> {
    let mut reconstructor =
        Reconstructor::new(basis, basis_length, block_size, output, output_limit)?;
    for instruction in instructions {
        reconstructor.apply(instruction)?;
    }
    reconstructor.finish(trailer)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconstructionStats {
    pub logical_bytes: u64,
    pub literal_bytes: u64,
}

pub struct Reconstructor<B, W> {
    basis: B,
    basis_length: u64,
    block_size: u64,
    output: W,
    output_limit: u64,
    actual: u64,
    literal: u64,
    hasher: blake3::Hasher,
    buffer: Vec<u8>,
}

impl<B: Read + Seek, W: Write> Reconstructor<B, W> {
    pub fn new(
        basis: B,
        basis_length: u64,
        block_size: usize,
        output: W,
        output_limit: u64,
    ) -> Result<Self> {
        validate_block_size(block_size)?;
        Ok(Self {
            basis,
            basis_length,
            block_size: block_size as u64,
            output,
            output_limit,
            actual: 0,
            literal: 0,
            hasher: blake3::Hasher::new(),
            buffer: vec![0; 64 * 1024],
        })
    }

    pub fn apply(&mut self, instruction: &Instruction) -> Result<()> {
        match instruction {
            Instruction::Literal(bytes) => {
                if bytes.len() > MAX_LITERAL {
                    return Err(Error::Protocol(
                        "literal exceeds negotiated chunk limit".into(),
                    ));
                }
                self.charge(bytes.len() as u64)?;
                self.output
                    .write_all(bytes)
                    .map_err(|error| Error::io(None, error))?;
                self.hasher.update(bytes);
                self.literal += bytes.len() as u64;
            }
            Instruction::Copy {
                first_block,
                block_count,
            } => {
                if *block_count == 0 {
                    return Err(Error::Protocol("zero-length delta copy".into()));
                }
                let end_block = first_block
                    .checked_add(u64::from(*block_count))
                    .ok_or_else(|| Error::Protocol("delta copy range overflow".into()))?;
                let available_blocks = self.basis_length.div_ceil(self.block_size);
                if end_block > available_blocks {
                    return Err(Error::Protocol("delta copy range exceeds basis".into()));
                }
                let start = first_block
                    .checked_mul(self.block_size)
                    .ok_or_else(|| Error::Protocol("invalid delta copy index".into()))?;
                let end = end_block
                    .checked_mul(self.block_size)
                    .ok_or_else(|| Error::Protocol("invalid delta copy range".into()))?
                    .min(self.basis_length);
                if start >= self.basis_length || end <= start {
                    return Err(Error::Protocol("delta copy index exceeds basis".into()));
                }
                self.charge(end - start)?;
                self.basis
                    .seek(SeekFrom::Start(start))
                    .map_err(|error| Error::io(None, error))?;
                let mut remaining = end - start;
                while remaining != 0 {
                    let wanted = usize::try_from(remaining.min(self.buffer.len() as u64))
                        .map_err(|_| Error::Protocol("copy length overflow".into()))?;
                    self.basis
                        .read_exact(&mut self.buffer[..wanted])
                        .map_err(|error| Error::io(None, error))?;
                    self.output
                        .write_all(&self.buffer[..wanted])
                        .map_err(|error| Error::io(None, error))?;
                    self.hasher.update(&self.buffer[..wanted]);
                    remaining -= wanted as u64;
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn bytes_written(&self) -> u64 {
        self.actual
    }

    #[must_use]
    pub const fn literal_bytes(&self) -> u64 {
        self.literal
    }

    pub fn finish(mut self, trailer: Trailer) -> Result<ReconstructionStats> {
        if self.actual != trailer.length || self.hasher.finalize().as_bytes() != &trailer.digest {
            return Err(Error::entry(
                "digest-mismatch",
                None,
                "delta digest or length mismatch",
            ));
        }
        self.output
            .flush()
            .map_err(|error| Error::io(None, error))?;
        Ok(ReconstructionStats {
            logical_bytes: self.actual,
            literal_bytes: self.literal,
        })
    }

    fn charge(&mut self, count: u64) -> Result<()> {
        self.actual = self
            .actual
            .checked_add(count)
            .ok_or_else(|| Error::Protocol("delta output length overflow".into()))?;
        if self.actual > self.output_limit {
            return Err(Error::Protocol("delta produced too much output".into()));
        }
        Ok(())
    }
}

fn validate_block_size(block_size: usize) -> Result<()> {
    if block_size == 0 || block_size > MAX_BLOCK_SIZE {
        return Err(Error::Protocol(format!(
            "delta block size must be between 1 and {MAX_BLOCK_SIZE}"
        )));
    }
    Ok(())
}

#[must_use]
pub fn weak_checksum(block: &[u8]) -> u32 {
    let mut a = 0u32;
    let mut b = 0u32;
    for (index, &byte) in block.iter().enumerate() {
        a = a.wrapping_add(u32::from(byte));
        b = b.wrapping_add(((block.len() - index) as u32).wrapping_mul(u32::from(byte)));
    }
    (b << 16) | (a & 0xffff)
}

fn strong16(block: &[u8]) -> [u8; 16] {
    let mut output = [0u8; 16];
    output.copy_from_slice(&blake3::hash(block).as_bytes()[..16]);
    output
}

fn fill_window<R: Read>(reader: &mut R, window: &mut VecDeque<u8>, size: usize) -> Result<bool> {
    let mut buffer = vec![0u8; (size - window.len()).min(64 * 1024)];
    while window.len() < size {
        let wanted = (size - window.len()).min(buffer.len());
        let count = reader
            .read(&mut buffer[..wanted])
            .map_err(|error| Error::io(None, error))?;
        if count == 0 {
            return Ok(true);
        }
        window.extend(&buffer[..count]);
    }
    Ok(false)
}

struct WeakState {
    a: u32,
    b: u32,
    length: u32,
}

impl WeakState {
    fn new(bytes: &VecDeque<u8>) -> Self {
        let mut a = 0u32;
        let mut b = 0u32;
        for (index, byte) in bytes.iter().copied().enumerate() {
            a = a.wrapping_add(u32::from(byte));
            b = b.wrapping_add(((bytes.len() - index) as u32).wrapping_mul(u32::from(byte)));
        }
        Self {
            a,
            b,
            length: bytes.len() as u32,
        }
    }

    const fn value(&self) -> u32 {
        (self.b << 16) | (self.a & 0xffff)
    }

    fn roll(&mut self, outgoing: u8, incoming: u8) {
        self.a = self
            .a
            .wrapping_sub(u32::from(outgoing))
            .wrapping_add(u32::from(incoming));
        self.b = self
            .b
            .wrapping_sub(self.length.wrapping_mul(u32::from(outgoing)))
            .wrapping_add(self.a);
    }
}

struct InstructionEmitter<F> {
    emit: F,
    literal: Vec<u8>,
    copy: Option<(u64, u32)>,
}

impl<F: FnMut(Instruction) -> Result<()>> InstructionEmitter<F> {
    fn new(emit: F) -> Self {
        Self {
            emit,
            literal: Vec::new(),
            copy: None,
        }
    }

    fn push_literal(&mut self, byte: u8) -> Result<()> {
        self.flush_copy()?;
        self.literal.push(byte);
        if self.literal.len() == MAX_LITERAL {
            self.flush_literal()?;
        }
        Ok(())
    }

    fn push_copy(&mut self, block: u64) -> Result<()> {
        self.flush_literal()?;
        if let Some((first, count)) = self.copy.as_mut()
            && first.saturating_add(u64::from(*count)) == block
            && *count < u32::MAX
        {
            *count += 1;
            return Ok(());
        }
        self.flush_copy()?;
        self.copy = Some((block, 1));
        Ok(())
    }

    fn flush_literal(&mut self) -> Result<()> {
        if !self.literal.is_empty() {
            (self.emit)(Instruction::Literal(std::mem::take(&mut self.literal)))?;
        }
        Ok(())
    }

    fn flush_copy(&mut self) -> Result<()> {
        if let Some((first_block, block_count)) = self.copy.take() {
            (self.emit)(Instruction::Copy {
                first_block,
                block_count,
            })?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        self.flush_literal()?;
        self.flush_copy()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn shifted_data_reuses_blocks() {
        let basis = b"abcdefghabcdefgh";
        let source = b"XXabcdefghabcdefghYY";
        let sigs = signatures(basis, 8).unwrap();
        let delta = generate(source, &sigs, 8).unwrap();
        assert!(
            delta
                .instructions
                .iter()
                .any(|instruction| matches!(instruction, Instruction::Copy { .. }))
        );
        assert_eq!(apply(basis, &delta, 1024).unwrap(), source);
    }

    #[test]
    fn adversarial_weak_collision_bucket_falls_back_to_literals() {
        let source = b"abcdefgh";
        let weak = weak_checksum(source);
        let mut signatures = Vec::new();
        for block_index in 0..=MAX_WEAK_CANDIDATES as u64 {
            signatures.push(Signature {
                block_index,
                length: source.len() as u32,
                weak,
                strong: if block_index == 0 {
                    strong16(source)
                } else {
                    [block_index as u8; 16]
                },
            });
        }
        let delta = generate(source, &signatures, source.len()).unwrap();
        assert!(
            delta
                .instructions
                .iter()
                .all(|instruction| matches!(instruction, Instruction::Literal(_)))
        );
        assert_eq!(apply(&[], &delta, source.len() as u64).unwrap(), source);
    }

    #[test]
    fn corrupt_copy_and_digest_fail() {
        let mut delta = generate(b"new", &signatures(b"old", 3).unwrap(), 3).unwrap();
        delta.instructions = vec![Instruction::Copy {
            first_block: 99,
            block_count: 1,
        }];
        assert!(apply(b"old", &delta, 1024).is_err());
        let mut delta = generate(b"new", &[], 4).unwrap();
        delta.trailer.digest = [0; 32];
        assert!(apply(b"", &delta, 1024).is_err());
    }

    #[test]
    fn zero_and_oversized_blocks_are_rejected_without_panicking() {
        assert!(signatures(b"basis", 0).is_err());
        assert!(generate(b"source", &[], 0).is_err());
        assert!(signatures_from_reader(&b"basis"[..], MAX_BLOCK_SIZE + 1, 1024).is_err());
    }

    #[test]
    fn streaming_generation_bounds_literals_and_reconstructs_to_writer() {
        let basis = vec![b'a'; 256 * 1024];
        let mut source = basis.clone();
        source.splice(17..17, b"shift".iter().copied());
        let signatures = signatures_with_budget(&basis, 4096, WIRE_SIGNATURE_BUDGET).unwrap();
        let mut instructions = Vec::new();
        let trailer = generate_stream(&source[..], &signatures, 4096, |instruction| {
            instructions.push(instruction);
            Ok(())
        })
        .unwrap();
        assert!(instructions.iter().all(|instruction| {
            !matches!(instruction, Instruction::Literal(bytes) if bytes.len() > MAX_LITERAL)
        }));
        let mut output = Vec::new();
        apply_stream(
            Cursor::new(&basis),
            basis.len() as u64,
            4096,
            &instructions,
            trailer,
            source.len() as u64,
            &mut output,
        )
        .unwrap();
        assert_eq!(output, source);
    }

    #[test]
    fn huge_copy_count_is_rejected_arithmetically() {
        let delta = Delta {
            block_size: 4096,
            instructions: vec![Instruction::Copy {
                first_block: u64::MAX,
                block_count: u32::MAX,
            }],
            trailer: Trailer {
                length: 1,
                digest: [0; 32],
            },
        };
        assert!(apply(b"x", &delta, 1).is_err());
    }

    #[test]
    fn copy_may_use_one_short_tail_but_not_extend_past_it() {
        let basis = b"abcde";
        let valid = Delta {
            block_size: 4,
            instructions: vec![Instruction::Copy {
                first_block: 1,
                block_count: 1,
            }],
            trailer: Trailer {
                length: 1,
                digest: *blake3::hash(b"e").as_bytes(),
            },
        };
        assert_eq!(apply(basis, &valid, 1).unwrap(), b"e");
        let mut invalid = valid;
        invalid.instructions = vec![Instruction::Copy {
            first_block: 1,
            block_count: 2,
        }];
        assert!(apply(basis, &invalid, 8).is_err());
    }

    proptest! {
        #[test]
        fn arbitrary_delta_reconstructs(basis: Vec<u8>, source: Vec<u8>, block in 1usize..128) {
            let sigs = signatures(&basis, block).unwrap();
            let delta = generate(&source, &sigs, block).unwrap();
            prop_assert_eq!(apply(&basis, &delta, source.len() as u64).unwrap(), source);
        }
    }
}
