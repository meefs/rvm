//! The payload of a `WASM` segment: a raw module, or `rvf-runtime`'s
//! `WasmHeader` followed by the module (rvm#84 item 2).
//!
//! `RvfStore::embed_wasm` (rvf-runtime 0.4.0, `store.rs`, `write_path.rs`
//! `write_wasm_seg`) writes `WasmHeader` (64 bytes, `wasm_magic` 0x5256574D
//! little-endian, so the bytes `4D 57 56 52`) followed by the bytecode as the
//! segment payload. `rvf-forge-core` and RVM's own tooling write the module
//! bare (`\0asm...`). Both are accepted here; neither reaches the WASM parser
//! with header bytes in front.
//!
//! Layout of the 64-byte header (all little endian):
//!
//! | offset | size | field |
//! |---|---|---|
//! | 0x00 | 4 | `wasm_magic` = 0x5256574D |
//! | 0x04 | 2 | `header_version` (1) |
//! | 0x06 | 1 | `role` (0..=4) |
//! | 0x07 | 1 | `target` (0..=4) |
//! | 0x08 | 2 | `required_features` |
//! | 0x0A | 2 | `export_count` |
//! | 0x0C | 4 | `bytecode_size` |
//! | 0x10 | 4 | `compressed_size` (0) |
//! | 0x14 | 1 | `compression` (0) |
//! | 0x15 | 1 | `min_memory_pages` |
//! | 0x16 | 1 | `max_memory_pages` |
//! | 0x17 | 1 | `table_count` |
//! | 0x18 | 32 | `bytecode_hash` |
//! | 0x38 | 1 | `bootstrap_priority` |
//! | 0x39 | 1 | `interpreter_type` |
//! | 0x3A | 6 | reserved, zero |
//!
//! ## What is checked, and what is not
//!
//! Fail closed on: a payload that starts with the magic but is shorter than 64
//! bytes; an unknown `header_version`, `role` or `target`; a compressed
//! module (RVM has no decompressor and will not hand compressed bytes to the
//! parser); non-zero reserved bytes; and any disagreement between
//! `bytecode_size` and the bytes actually present (too few **or** too many).
//!
//! `bytecode_hash` is **not** checked. `rvf-runtime` fills it with a private
//! non-cryptographic mixing function (its source says so), not the SHAKE-256
//! the field is documented to hold, so it proves nothing and checking it would
//! bind RVM to that function. Authenticity of the module comes from the
//! segment's content hash and signature, both of which cover the header and
//! the bytecode together (the signature message hashes the whole payload), and
//! from the SHA-256 identity RVM records for the bytes it will execute.

use sha2::{Digest, Sha256};

/// Size of `rvf-runtime`'s `WasmHeader`.
pub const WASM_HEADER_LEN: usize = 64;

/// `WasmHeader::wasm_magic`: "RVWM" read as a big-endian number; on the wire
/// the little-endian bytes are `4D 57 56 52`.
pub const WASM_HEADER_MAGIC: u32 = 0x5256_574D;

const MAGIC_BYTES: [u8; 4] = WASM_HEADER_MAGIC.to_le_bytes();

/// Why a `WASM` segment payload was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmPayloadError {
    /// The payload starts with the `WasmHeader` magic but ends inside the
    /// 64-byte header.
    TruncatedHeader,
    /// `header_version` is not 1.
    UnsupportedVersion(u16),
    /// `role` or `target` is outside the values `rvf-types` defines.
    UnknownEnumValue,
    /// The header says the bytecode is compressed. RVM does not decompress.
    Compressed,
    /// The reserved bytes are not all zero.
    ReservedNonZero,
    /// `bytecode_size` is zero.
    EmptyBytecode,
    /// `bytecode_size` disagrees with the bytes present after the header.
    LengthMismatch,
}

impl core::fmt::Display for WasmPayloadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TruncatedHeader => f.write_str("WASM header is cut short"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported WASM header version {v}"),
            Self::UnknownEnumValue => f.write_str("WASM header role or target is unknown"),
            Self::Compressed => f.write_str("WASM bytecode is compressed"),
            Self::ReservedNonZero => f.write_str("WASM header reserved bytes are not zero"),
            Self::EmptyBytecode => f.write_str("WASM header declares an empty module"),
            Self::LengthMismatch => {
                f.write_str("WASM header bytecode_size disagrees with the payload")
            }
        }
    }
}

/// Where the module sits inside a `WASM` segment payload, and its identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleSpan {
    /// Offset of the first module byte within the payload: 0 for a bare
    /// module, [`WASM_HEADER_LEN`] when a `WasmHeader` precedes it.
    pub offset: u64,
    /// Module length in bytes.
    pub len: u64,
    /// SHA-256 of the module bytes (without any header).
    pub sha256: [u8; 32],
}

/// What a payload turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmPayloadFacts {
    /// No header: the whole payload is the module.
    Bare(ModuleSpan),
    /// A valid `WasmHeader` followed by exactly `bytecode_size` module bytes.
    Headed(ModuleSpan),
    /// A header that is malformed or lies about the bytes that follow.
    Rejected(WasmPayloadError),
}

/// Validate the fields of a complete 64-byte header and return its declared
/// bytecode size.
fn parse_header(head: &[u8; WASM_HEADER_LEN]) -> Result<u64, WasmPayloadError> {
    let version = u16::from_le_bytes([head[4], head[5]]);
    if version != 1 {
        return Err(WasmPayloadError::UnsupportedVersion(version));
    }
    if head[6] > 4 || head[7] > 4 {
        return Err(WasmPayloadError::UnknownEnumValue);
    }
    let compressed = u32::from_le_bytes([head[0x10], head[0x11], head[0x12], head[0x13]]);
    if compressed != 0 || head[0x14] != 0 {
        return Err(WasmPayloadError::Compressed);
    }
    if head[0x3A..0x40].iter().any(|&b| b != 0) {
        return Err(WasmPayloadError::ReservedNonZero);
    }
    let size = u32::from_le_bytes([head[0x0C], head[0x0D], head[0x0E], head[0x0F]]);
    if size == 0 {
        return Err(WasmPayloadError::EmptyBytecode);
    }
    Ok(u64::from(size))
}

#[derive(Clone, Copy)]
enum Mode {
    /// Fewer than 4 bytes seen.
    Undecided,
    /// No header; every byte is module.
    Bare,
    /// Magic seen; collecting the 64-byte header.
    Header,
    /// Header valid; the rest is module, up to `want` bytes.
    Body {
        want: u64,
    },
    Failed(WasmPayloadError),
}

/// Splits a `WASM` segment payload into header and module as it arrives, in
/// order, in pieces of any size.
///
/// Module bytes are handed to the sink and nowhere else: header bytes never
/// reach it, and bytes beyond the declared `bytecode_size` never reach it.
pub struct WasmPayloadScanner {
    mode: Mode,
    head: [u8; WASM_HEADER_LEN],
    have: usize,
    len: u64,
    sha: Sha256,
}

impl Default for WasmPayloadScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmPayloadScanner {
    /// A scanner at the start of a payload.
    #[must_use]
    pub fn new() -> Self {
        Self {
            mode: Mode::Undecided,
            head: [0; WASM_HEADER_LEN],
            have: 0,
            len: 0,
            sha: Sha256::new(),
        }
    }

    fn emit(&mut self, bytes: &[u8], sink: &mut impl FnMut(&[u8])) {
        if !bytes.is_empty() {
            self.sha.update(bytes);
            self.len += bytes.len() as u64;
            sink(bytes);
        }
    }

    /// Feed the next in-order payload bytes. Module bytes are passed to `sink`
    /// (zero, one or two calls).
    ///
    /// # Errors
    ///
    /// The header is malformed, or more bytes arrived than it declares. The
    /// scanner is then failed for good: later calls return the same error and
    /// emit nothing.
    pub fn push(
        &mut self,
        mut bytes: &[u8],
        mut sink: impl FnMut(&[u8]),
    ) -> Result<(), WasmPayloadError> {
        loop {
            match self.mode {
                Mode::Failed(e) => return Err(e),
                Mode::Bare => {
                    self.emit(bytes, &mut sink);
                    return Ok(());
                }
                Mode::Undecided | Mode::Header => {
                    let take = (WASM_HEADER_LEN - self.have).min(bytes.len());
                    self.head[self.have..self.have + take].copy_from_slice(&bytes[..take]);
                    self.have += take;
                    bytes = &bytes[take..];
                    if matches!(self.mode, Mode::Undecided) && self.have >= MAGIC_BYTES.len() {
                        if self.head[..4] == MAGIC_BYTES {
                            self.mode = Mode::Header;
                        } else {
                            self.mode = Mode::Bare;
                            let held = self.head;
                            let n = self.have;
                            self.emit(&held[..n], &mut sink);
                            continue;
                        }
                    }
                    if matches!(self.mode, Mode::Header) && self.have == WASM_HEADER_LEN {
                        match parse_header(&self.head) {
                            Ok(want) => self.mode = Mode::Body { want },
                            Err(e) => {
                                self.mode = Mode::Failed(e);
                                return Err(e);
                            }
                        }
                        continue;
                    }
                    return Ok(());
                }
                Mode::Body { want } => {
                    let room = want - self.len;
                    if bytes.len() as u64 > room {
                        self.mode = Mode::Failed(WasmPayloadError::LengthMismatch);
                        return Err(WasmPayloadError::LengthMismatch);
                    }
                    self.emit(bytes, &mut sink);
                    return Ok(());
                }
            }
        }
    }

    /// The payload ended. Short payloads with no magic are bare modules (the
    /// parser will judge them); a header with too few module bytes is refused.
    #[must_use]
    pub fn finish(mut self, mut sink: impl FnMut(&[u8])) -> WasmPayloadFacts {
        let held = self.head;
        let n = self.have;
        let facts = |s: Self, bare: bool| {
            let span = ModuleSpan {
                offset: if bare { 0 } else { WASM_HEADER_LEN as u64 },
                len: s.len,
                sha256: s.sha.finalize().into(),
            };
            if bare {
                WasmPayloadFacts::Bare(span)
            } else {
                WasmPayloadFacts::Headed(span)
            }
        };
        match self.mode {
            Mode::Failed(e) => WasmPayloadFacts::Rejected(e),
            Mode::Undecided => {
                self.emit(&held[..n], &mut sink);
                facts(self, true)
            }
            Mode::Bare => facts(self, true),
            Mode::Header => WasmPayloadFacts::Rejected(WasmPayloadError::TruncatedHeader),
            Mode::Body { want } if self.len == want => facts(self, false),
            Mode::Body { .. } => WasmPayloadFacts::Rejected(WasmPayloadError::LengthMismatch),
        }
    }
}

/// Split a whole `WASM` segment payload into its module bytes.
///
/// A bare module is returned as is. A payload that starts with the `WasmHeader`
/// magic is validated (see the module docs) and the header is removed.
///
/// # Errors
///
/// [`WasmPayloadError`] when a header is present and malformed or inconsistent
/// with the bytes that follow it.
pub fn split_wasm_payload(payload: &[u8]) -> Result<&[u8], WasmPayloadError> {
    let mut sc = WasmPayloadScanner::new();
    sc.push(payload, |_| {})?;
    match sc.finish(|_| {}) {
        WasmPayloadFacts::Bare(_) => Ok(payload),
        WasmPayloadFacts::Headed(span) => Ok(&payload[span.offset as usize..]),
        WasmPayloadFacts::Rejected(e) => Err(e),
    }
}

/// The module facts of a whole payload (used by the buffered verifier).
#[must_use]
pub(crate) fn scan_payload(payload: &[u8]) -> WasmPayloadFacts {
    let mut sc = WasmPayloadScanner::new();
    match sc.push(payload, |_| {}) {
        Ok(()) => sc.finish(|_| {}),
        Err(e) => WasmPayloadFacts::Rejected(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const MODULE: &[u8] = b"\0asm\x01\0\0\0";

    fn header(size: u32) -> [u8; WASM_HEADER_LEN] {
        let mut h = [0u8; WASM_HEADER_LEN];
        h[..4].copy_from_slice(&MAGIC_BYTES);
        h[4] = 1;
        h[0x0C..0x10].copy_from_slice(&size.to_le_bytes());
        h
    }

    fn headed(size: u32, body: &[u8]) -> Vec<u8> {
        let mut v = header(size).to_vec();
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn a_bare_module_passes_through() {
        assert_eq!(split_wasm_payload(MODULE).unwrap(), MODULE);
        assert_eq!(split_wasm_payload(b"").unwrap(), b"");
        assert_eq!(split_wasm_payload(b"\0as").unwrap(), b"\0as");
    }

    #[test]
    fn a_header_is_stripped() {
        let p = headed(MODULE.len() as u32, MODULE);
        assert_eq!(split_wasm_payload(&p).unwrap(), MODULE);
    }

    #[test]
    fn every_split_of_a_headed_payload_yields_the_same_module() {
        let p = headed(MODULE.len() as u32, MODULE);
        for cut in 0..=p.len() {
            let mut sc = WasmPayloadScanner::new();
            let mut got = Vec::new();
            sc.push(&p[..cut], |m| got.extend_from_slice(m)).unwrap();
            sc.push(&p[cut..], |m| got.extend_from_slice(m)).unwrap();
            let facts = sc.finish(|m| got.extend_from_slice(m));
            assert_eq!(got, MODULE, "cut {cut}");
            assert!(matches!(facts, WasmPayloadFacts::Headed(_)));
        }
    }

    #[test]
    fn lying_or_malformed_headers_are_refused() {
        let ok = MODULE.len() as u32;
        // Truncated header (starts with the magic).
        assert_eq!(
            split_wasm_payload(&header(ok)[..63]),
            Err(WasmPayloadError::TruncatedHeader)
        );
        assert_eq!(
            split_wasm_payload(&MAGIC_BYTES),
            Err(WasmPayloadError::TruncatedHeader)
        );
        // bytecode_size larger than what follows, and smaller.
        assert_eq!(
            split_wasm_payload(&headed(ok + 1, MODULE)),
            Err(WasmPayloadError::LengthMismatch)
        );
        assert_eq!(
            split_wasm_payload(&headed(ok - 1, MODULE)),
            Err(WasmPayloadError::LengthMismatch)
        );
        // Header only.
        assert_eq!(
            split_wasm_payload(&header(ok)),
            Err(WasmPayloadError::LengthMismatch)
        );
        assert_eq!(
            split_wasm_payload(&headed(0, MODULE)),
            Err(WasmPayloadError::EmptyBytecode)
        );
        let mut h = headed(ok, MODULE);
        h[4] = 2;
        assert_eq!(
            split_wasm_payload(&h),
            Err(WasmPayloadError::UnsupportedVersion(2))
        );
        let mut h = headed(ok, MODULE);
        h[6] = 9;
        assert_eq!(
            split_wasm_payload(&h),
            Err(WasmPayloadError::UnknownEnumValue)
        );
        let mut h = headed(ok, MODULE);
        h[0x10] = 1;
        assert_eq!(split_wasm_payload(&h), Err(WasmPayloadError::Compressed));
        let mut h = headed(ok, MODULE);
        h[0x14] = 1;
        assert_eq!(split_wasm_payload(&h), Err(WasmPayloadError::Compressed));
        let mut h = headed(ok, MODULE);
        h[0x3F] = 1;
        assert_eq!(
            split_wasm_payload(&h),
            Err(WasmPayloadError::ReservedNonZero)
        );
    }

    #[test]
    fn extra_bytes_never_reach_the_sink() {
        let p = headed(MODULE.len() as u32, &[MODULE, b"EXTRA"].concat());
        let mut sc = WasmPayloadScanner::new();
        let mut got = Vec::new();
        assert!(sc.push(&p, |m| got.extend_from_slice(m)).is_err());
        assert!(got.is_empty(), "nothing is released past a lying length");
    }
}
