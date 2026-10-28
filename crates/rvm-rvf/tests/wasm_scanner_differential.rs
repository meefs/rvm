//! Adversarial review of PR #87: differential tests for WasmPayloadScanner.
use rvm_rvf::{
    split_wasm_payload, WasmPayloadError, WasmPayloadFacts, WasmPayloadScanner, WASM_HEADER_LEN,
    WASM_HEADER_MAGIC,
};
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, Eq)]
enum Out {
    Ok {
        module: Vec<u8>,
        offset: u64,
        len: u64,
        sha: [u8; 32],
        headed: bool,
    },
    Err(WasmPayloadError),
}

fn run(payload: &[u8], cuts: &[usize]) -> Out {
    let mut sc = WasmPayloadScanner::new();
    let mut got = Vec::new();
    let mut prev = 0;
    let mut bounds: Vec<usize> = cuts
        .iter()
        .copied()
        .filter(|&c| c <= payload.len())
        .collect();
    bounds.push(payload.len());
    for b in bounds {
        if b < prev {
            continue;
        }
        if let Err(e) = sc.push(&payload[prev..b], |m| got.extend_from_slice(m)) {
            return Out::Err(e);
        }
        prev = b;
    }
    match sc.finish(|m| got.extend_from_slice(m)) {
        WasmPayloadFacts::Bare(s) | WasmPayloadFacts::Headed(s) => {
            let headed = s.offset != 0;
            Out::Ok {
                module: got,
                offset: s.offset,
                len: s.len,
                sha: s.sha256,
                headed,
            }
        }
        WasmPayloadFacts::Rejected(e) => Out::Err(e),
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn header(size: u32) -> Vec<u8> {
    let mut h = vec![0u8; WASM_HEADER_LEN];
    h[..4].copy_from_slice(&WASM_HEADER_MAGIC.to_le_bytes());
    h[4] = 1;
    h[0x0C..0x10].copy_from_slice(&size.to_le_bytes());
    h
}

fn corpus(r: &mut Rng) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = Vec::new();
    for body_len in [0usize, 1, 3, 4, 8, 63, 64, 65, 200] {
        let body: Vec<u8> = (0..body_len).map(|_| r.next() as u8).collect();
        for delta in [-2i64, -1, 0, 1, 2] {
            let size = (body_len as i64 + delta).clamp(0, u32::MAX as i64) as u32;
            let mut p = header(size);
            p.extend_from_slice(&body);
            v.push(p);
        }
        v.push(body.clone());
        let mut m = b"\0asm\x01\0\0\0".to_vec();
        m.extend_from_slice(&body);
        v.push(m);
        // raw module containing the magic after offset 0 and header-like bytes
        let mut m2 = b"\0asm\x01\0\0\0".to_vec();
        m2.extend_from_slice(&header(5));
        m2.extend_from_slice(&body);
        v.push(m2);
    }
    // truncated headers at every length
    let full = header(8);
    for n in 0..=WASM_HEADER_LEN {
        v.push(full[..n].to_vec());
    }
    // header field mutations
    for _ in 0..300 {
        let mut p = header(8);
        p.extend_from_slice(b"\0asm\x01\0\0\0");
        let i = (r.next() as usize) % WASM_HEADER_LEN;
        p[i] = r.next() as u8;
        if r.next() % 4 == 0 {
            let j = (r.next() as usize) % p.len();
            p[j] ^= 0xff;
        }
        v.push(p);
    }
    // huge declared size
    let mut p = header(u32::MAX);
    p.extend_from_slice(b"\0asm\x01\0\0\0");
    v.push(p);
    v
}

#[test]
fn differential_whole_vs_every_split_vs_one_byte_vs_random() {
    let mut r = Rng(0x9E3779B97F4A7C15);
    for p in corpus(&mut r) {
        let whole = run(&p, &[]);
        // one byte at a time
        let all: Vec<usize> = (1..p.len()).collect();
        assert_eq!(run(&p, &all), whole, "1-byte vs whole, len {}", p.len());
        // every single cut
        for c in 0..=p.len() {
            assert_eq!(run(&p, &[c]), whole, "cut {c} len {}", p.len());
        }
        // random multi-cuts
        for _ in 0..8 {
            let mut cuts: Vec<usize> = (0..4)
                .map(|_| (r.next() as usize) % (p.len() + 1))
                .collect();
            cuts.sort_unstable();
            assert_eq!(run(&p, &cuts), whole, "cuts {cuts:?} len {}", p.len());
        }
        // split_wasm_payload agrees with whole; and sha/len/offset consistent with emitted bytes
        match &whole {
            Out::Ok {
                module,
                offset,
                len,
                sha,
                headed,
            } => {
                assert_eq!(*len as usize, module.len());
                assert_eq!(*sha, <[u8; 32]>::from(Sha256::digest(module)));
                assert_eq!(
                    &p[*offset as usize..],
                    &module[..],
                    "module is exactly payload[offset..]"
                );
                assert_eq!(split_wasm_payload(&p).unwrap(), &module[..]);
                assert_eq!(*headed, *offset == 64);
                if *headed {
                    assert_eq!(&p[..4], &WASM_HEADER_MAGIC.to_le_bytes());
                }
            }
            Out::Err(e) => assert_eq!(split_wasm_payload(&p), Err(*e)),
        }
    }
}

/// bytecode_size u32::MAX with a tiny body must not allocate or overflow.
#[test]
fn huge_declared_size_is_refused_at_finish_without_overflow() {
    let mut p = header(u32::MAX);
    p.extend_from_slice(b"\0asm\x01\0\0\0");
    assert_eq!(
        split_wasm_payload(&p),
        Err(WasmPayloadError::LengthMismatch)
    );
}
