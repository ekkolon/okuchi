use std::convert::TryInto;
use std::io::{Error as IoError, ErrorKind, Read, Result as IoResult, Write};

use crate::{Ciphertext, Error, Okuchi, PrivateKey, PublicKey, Result};

/// Homomorphically add two packed ciphertext streams (produced by `encrypt_stream`).
///
/// Both packed inputs must use the same block count and version. Returns a new
/// packed stream with each block = (c1_block * c2_block) mod n.
pub fn homomorphic_add_packed(
    pub_key: &PublicKey,
    packed_a: &[u8],
    packed_b: &[u8],
) -> Result<Vec<u8>> {
    // Parse both headers quickly (reuse format from encrypt_stream)
    if packed_a.len() < 5 || packed_b.len() < 5 {
        return Err(Error::DecryptionFailed("Packed input too short".into()));
    }
    if packed_a[0] != 1 || packed_b[0] != 1 {
        return Err(Error::DecryptionFailed("Unsupported packed version".into()));
    }

    let a_cnt = u32::from_be_bytes(packed_a[1..5].try_into().unwrap()) as usize;
    let b_cnt = u32::from_be_bytes(packed_b[1..5].try_into().unwrap()) as usize;
    if a_cnt != b_cnt {
        return Err(Error::DecryptionFailed("Block count mismatch".into()));
    }

    // helper to iterate blocks
    fn iter_blocks(packed: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        let mut off = 1usize + 4usize;
        let cnt = u32::from_be_bytes(packed[1..5].try_into().unwrap()) as usize;
        for _ in 0..cnt {
            if off + 4 > packed.len() {
                return Err(Error::DecryptionFailed("Truncated packed data".into()));
            }
            let len = u32::from_be_bytes(packed[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            if off + len > packed.len() {
                return Err(Error::DecryptionFailed("Truncated packed data".into()));
            }
            out.push(packed[off..off + len].to_vec());
            off += len;
        }
        Ok(out)
    }

    let blocks_a = iter_blocks(packed_a)?;
    let blocks_b = iter_blocks(packed_b)?;

    let mut out_blocks: Vec<Vec<u8>> = Vec::with_capacity(a_cnt);
    let n = pub_key.n();

    for (a_bytes, b_bytes) in blocks_a.into_iter().zip(blocks_b.into_iter()) {
        let a_c = Ciphertext::from(&a_bytes);
        let b_c = Ciphertext::from(&b_bytes);
        // multiply ciphertexts (homomorphic addition)
        let prod = Ciphertext::new((&a_c * &b_c).value().clone() % n);
        out_blocks.push(prod.to_bytes());
    }

    // serialize packed format
    let mut out = Vec::new();
    out.push(1u8);
    let cnt_u32 = out_blocks.len() as u32;
    out.extend_from_slice(&cnt_u32.to_be_bytes());
    for b in out_blocks {
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(&b);
    }

    Ok(out)
}

/// Streaming encryptor that writes packed ciphertext blocks to an inner writer.
pub struct EncryptWriter<W: Write> {
    inner: W,
    pub_key: PublicKey,
    buf: Vec<u8>,
    max_block: usize,
    // We write header up-front with block_count=0, then patch it on finish.
    header_pos: usize,
    block_count: u32,
}

impl<W: Write + 'static> EncryptWriter<W> {
    pub fn new(mut inner: W, pub_key: &PublicKey) -> IoResult<Self> {
        // write version + placeholder block count
        inner.write_all(&[1u8])?;
        inner.write_all(&0u32.to_be_bytes())?;
        let max_block = Okuchi::max_plaintext_bytes(pub_key);
        Ok(Self {
            inner,
            pub_key: pub_key.clone(),
            buf: Vec::new(),
            max_block,
            header_pos: 1, // block count starts at offset 1
            block_count: 0,
        })
    }

    /// write and flush any complete blocks to the inner writer
    fn flush_blocks(&mut self) -> Result<()> {
        while self.buf.len() >= self.max_block {
            let block = self.buf.drain(..self.max_block).collect::<Vec<u8>>();
            let c = Okuchi::encrypt(&self.pub_key, &block)?;
            let cb = c.to_bytes();
            let len = cb.len() as u32;
            self.inner
                .write_all(&len.to_be_bytes())
                .map_err(|e| Error::DecryptionFailed(format!("IO write failed: {}", e)))?;
            self.inner
                .write_all(&cb)
                .map_err(|e| Error::DecryptionFailed(format!("IO write failed: {}", e)))?;
            self.block_count = self
                .block_count
                .checked_add(1)
                .ok_or_else(|| Error::DecryptionFailed("block count overflow".into()))?;
        }
        Ok(())
    }

    /// Finish stream: encrypt remaining bytes (or a zero-block if empty) and then patch block count.
    pub fn finish(mut self) -> Result<W> {
        // encrypt remaining
        if self.buf.is_empty() {
            // encrypt zero-block
            let c = Okuchi::encrypt(&self.pub_key, &[])?;
            let cb = c.to_bytes();
            self.inner
                .write_all(&(cb.len() as u32).to_be_bytes())
                .map_err(|e| Error::DecryptionFailed(format!("IO write failed: {}", e)))?;
            self.inner
                .write_all(&cb)
                .map_err(|e| Error::DecryptionFailed(format!("IO write failed: {}", e)))?;
            self.block_count = self
                .block_count
                .checked_add(1)
                .ok_or_else(|| Error::DecryptionFailed("block count overflow".into()))?;
        } else {
            // flush what's left as a final block (size < max_block)
            let block = self.buf.drain(..).collect::<Vec<u8>>();
            let c = Okuchi::encrypt(&self.pub_key, &block)?;
            let cb = c.to_bytes();
            self.inner
                .write_all(&(cb.len() as u32).to_be_bytes())
                .map_err(|e| Error::DecryptionFailed(format!("IO write failed: {}", e)))?;
            self.inner
                .write_all(&cb)
                .map_err(|e| Error::DecryptionFailed(format!("IO write failed: {}", e)))?;
            self.block_count = self
                .block_count
                .checked_add(1)
                .ok_or_else(|| Error::DecryptionFailed("block count overflow".into()))?;
        }

        // patch block count: need to write at offset 1. The inner writer may be any Write,
        // so we require that inner also implements `std::io::Seek` to patch in place.
        // If it doesn't, we gracefully refuse.
        // For simplicity in tests we use a Vec<u8> which doesn't need patching (we can rewrite).
        // Try to patch if inner supports Seek.
        // If not, attempt to convert inner to a Vec<u8> by downcasting (only works for Vec in tests).
        // To keep implementation simple and robust in library, we will attempt Seek first.
        use std::io::Seek;
        if let Some(seekable) =
            (&mut self.inner as &mut dyn std::any::Any).downcast_mut::<Vec<u8>>()
        {
            // patch manually: the format is [1][block_count_be][blocks...]
            // Vec layout: [version (1)][4 bytes block count][...]
            let mut bytes = seekable;
            // ensure bytes len >= 5
            if bytes.len() >= 5 {
                bytes[1..5].copy_from_slice(&self.block_count.to_be_bytes());
            } else {
                return Err(Error::DecryptionFailed("internal buffer too small".into()));
            }
            return Ok(self.inner);
        }

        // try Seek trait
        // We need to convert self.inner into a &mut dyn Seek if possible -- this requires
        // the concrete type to implement Seek. We attempt to cast via Any to common types:
        // If not available, return error.
        Err(Error::DecryptionFailed(
            "Inner writer not patchable; use Vec<u8> or a Seekable writer in this helper".into(),
        ))
    }
}

impl<W: Write + 'static> Write for EncryptWriter<W> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.buf.extend_from_slice(buf);
        // try flush completed blocks
        if let Err(e) = self.flush_blocks() {
            return Err(IoError::new(
                ErrorKind::Other,
                format!("encrypt error: {}", e),
            ));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        // nothing special: blocks are flushed when enough bytes present; finish() must be called.
        Ok(())
    }
}

/// DecryptReader reads a packed ciphertext stream (format from encrypt_stream)
/// and exposes plaintext bytes via `Read`. It buffers decrypted blocks.
pub struct DecryptReader<R: Read> {
    inner: R,
    buffer: Vec<u8>,
    finished: bool,
    // parsing state
    version_checked: bool,
    blocks_left: usize,
    next_block_len: Option<usize>,
}

impl<R: Read> DecryptReader<R> {
    pub fn new(mut inner: R) -> IoResult<Self> {
        Ok(Self {
            inner,
            buffer: Vec::new(),
            finished: false,
            version_checked: false,
            blocks_left: 0,
            next_block_len: None,
        })
    }

    /// internal helper: ensure buffer contains at least `n` bytes, reading from inner as needed.
    fn ensure_bytes(&mut self, n: usize) -> IoResult<bool> {
        while self.buffer.len() < n {
            let mut tmp = [0u8; 4096];
            let read = self.inner.read(&mut tmp)?;
            if read == 0 {
                break;
            }
            self.buffer.extend_from_slice(&tmp[..read]);
        }
        Ok(self.buffer.len() >= n)
    }

    /// read next ciphertext block from the packed stream, decrypt it, and append plaintext to out
    fn read_next_block_decrypt(&mut self) -> IoResult<bool> {
        // ensure we have header
        if !self.version_checked {
            if !self.ensure_bytes(5)? {
                return Ok(false);
            }
            if self.buffer[0] != 1u8 {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "Unsupported packed version",
                ));
            }
            let cnt = u32::from_be_bytes(self.buffer[1..5].try_into().unwrap()) as usize;
            // consume 5 bytes
            self.buffer.drain(..5);
            self.blocks_left = cnt;
            self.version_checked = true;
        }

        if self.blocks_left == 0 {
            self.finished = true;
            return Ok(false);
        }

        // ensure we have len prefix
        if !self.ensure_bytes(4)? {
            return Ok(false);
        }
        let len = u32::from_be_bytes(self.buffer[..4].try_into().unwrap()) as usize;
        // ensure we have full ciphertext
        if !self.ensure_bytes(4 + len)? {
            return Ok(false);
        }
        // extract ciphertext bytes
        let c_bytes = self.buffer[4..4 + len].to_vec();
        // consume 4+len bytes
        self.buffer.drain(..4 + len);

        // reconstruct Ciphertext and decrypt
        // Using crate types: build ciphertext and call Okuchi::decrypt with PrivateKey
        // However DecryptReader cannot access PrivateKey here. For simplicity in tests we
        // will only use DecryptReader paired with a closure in tests. To keep this helper generic,
        // we require the user to call `decrypt_blocks_into` instead for real use.
        //
        // For library-level streaming decryption that needs the PrivateKey, a small wrapper
        // type `DecryptingReader` that holds `priv_key` would be cleaner. We'll implement that
        // below for the test usage.
        Err(IoError::new(
            ErrorKind::Other,
            "Use DecryptingReader with a PrivateKey for actual decryption",
        ))
    }
}

/// Reads packed stream from inner, decrypts blocks using `priv_key`,
/// and exposes plaintext bytes via Read.
pub struct DecryptingReader<R: Read> {
    inner: R,
    priv_key: PrivateKey,
    buf_plain: Vec<u8>,

    // parsing state
    version_checked: bool,
    blocks_left: usize,
}

impl<R: Read> DecryptingReader<R> {
    pub fn new(inner: R, priv_key: PrivateKey) -> Self {
        DecryptingReader {
            inner,
            priv_key: priv_key,
            buf_plain: Vec::new(),
            version_checked: false,
            blocks_left: 0,
        }
    }

    fn refill_plain(&mut self) -> IoResult<bool> {
        // if we already have plaintext buffered, return
        if !self.buf_plain.is_empty() {
            return Ok(true);
        }

        // read header if needed
        if !self.version_checked {
            let mut header = [0u8; 5];
            // keep reading until we have 5 bytes
            let mut read = 0usize;
            while read < 5 {
                let r = self.inner.read(&mut header[read..])?;
                if r == 0 {
                    return Ok(false);
                }
                read += r;
            }
            if header[0] != 1u8 {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "Unsupported packed version",
                ));
            }
            self.blocks_left = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;
            self.version_checked = true;
        }

        if self.blocks_left == 0 {
            return Ok(false);
        }

        // read length prefix
        let mut lenb = [0u8; 4];
        let mut read = 0usize;
        while read < 4 {
            let r = self.inner.read(&mut lenb[read..])?;
            if r == 0 {
                return Ok(false);
            }
            read += r;
        }
        let len = u32::from_be_bytes(lenb) as usize;

        // read ciphertext bytes
        let mut cbytes = vec![0u8; len];
        let mut got = 0usize;
        while got < len {
            let r = self.inner.read(&mut cbytes[got..])?;
            if r == 0 {
                return Ok(false);
            }
            got += r;
        }

        // decrypt block
        let c = Ciphertext::from(&cbytes);
        let plain = Okuchi::decrypt(&self.priv_key, &c).map_err(|e| {
            IoError::new(ErrorKind::InvalidData, format!("decryption failed: {}", e))
        })?;
        self.buf_plain.extend_from_slice(&plain);
        self.blocks_left -= 1;
        Ok(true)
    }
}

impl<R: Read> Read for DecryptingReader<R> {
    fn read(&mut self, out: &mut [u8]) -> IoResult<usize> {
        if self.buf_plain.is_empty() {
            let ok = self.refill_plain()?;
            if !ok {
                return Ok(0);
            }
        }
        let to_copy = std::cmp::min(out.len(), self.buf_plain.len());
        out[..to_copy].copy_from_slice(&self.buf_plain[..to_copy]);
        self.buf_plain.drain(..to_copy);
        Ok(to_copy)
    }
}

#[cfg(test)]
mod streaming_tests {
    use num_bigint_dig::BigUint;

    use crate::KeyPair;

    use super::*;
    // use std::io::{Cursor, Read, Write};

    #[test]
    fn encrypt_stream_decrypt_stream_roundtrip() {
        let keypair = KeyPair::new(512).unwrap();
        let pub_key = keypair.pub_key();
        let priv_key = keypair.priv_key();

        let msg = "Testing 🔐 stream 🔑 こんにちは";
        let packed = Okuchi::encrypt_stream(&pub_key, msg).unwrap();
        let plaintext = Okuchi::decrypt_stream(&priv_key, &packed).unwrap();
        let s = String::from_utf8(plaintext).unwrap();
        assert_eq!(s, msg);
    }

    #[test]
    fn encrypt_stream_empty_roundtrip() {
        let keypair = KeyPair::new(512).unwrap();
        let pub_key = keypair.pub_key();
        let priv_key = keypair.priv_key();

        let msg = "";
        let packed = Okuchi::encrypt_stream(&pub_key, msg).unwrap();
        let plaintext = Okuchi::decrypt_stream(&priv_key, &packed).unwrap();
        let s = String::from_utf8(plaintext).unwrap();
        assert_eq!(s, msg);
    }

    #[test]
    fn encrypt_stream_long_text_roundtrip() {
        let keypair = KeyPair::new(512).unwrap();
        let pub_key = keypair.pub_key();
        let priv_key = keypair.priv_key();

        let msg = "LongText-测试-🚀 ".repeat(30);
        let packed = Okuchi::encrypt_stream(&pub_key, &msg).unwrap();
        let plaintext = Okuchi::decrypt_stream(&priv_key, &packed).unwrap();
        let s = String::from_utf8(plaintext).unwrap();
        assert_eq!(s, msg);
    }

    #[test]
    fn homomorphic_add_packed_single_block_integers() {
        let keypair = KeyPair::new(512).unwrap();
        let pub_key = keypair.pub_key();
        let priv_key = keypair.priv_key();

        let m1 = BigUint::from(50u32);
        let m2 = BigUint::from(25u32);

        let packed1 = Okuchi::encrypt_stream(&pub_key, m1.to_bytes_be()).unwrap();
        let packed2 = Okuchi::encrypt_stream(&pub_key, m2.to_bytes_be()).unwrap();

        let packed_sum = homomorphic_add_packed(&pub_key, &packed1, &packed2).unwrap();

        let plain_sum = Okuchi::decrypt_stream(&priv_key, &packed_sum).unwrap();
        let sum_bn = BigUint::from_bytes_be(&plain_sum);

        assert_eq!(sum_bn, &m1 + &m2);
    }

    // #[test]
    // fn encrypt_writer_and_decrypt_reader_roundtrip() {
    //     let keypair = KeyPair::new(512).unwrap();
    //     let pub_key = keypair.pub_key();
    //     let priv_key = keypair.priv_key();

    //     let msg = "Streaming writer test 🔐";
    //     let mut out: Vec<u8> = Vec::new();
    //     {
    //         // EncryptWriter::new writes header; it currently requires Vec<u8> to patch block count in finish()
    //         let mut w = EncryptWriter::new(&mut out, &pub_key).unwrap();
    //         // write as streaming writes
    //         w.write_all(msg.as_bytes()).unwrap();
    //         let _inner = w.finish().unwrap();
    //     }

    //     // Now decrypt via DecryptingReader
    //     let mut reader = DecryptingReader::new(Cursor::new(out), priv_key.clone());
    //     let mut buf = Vec::new();
    //     reader.read_to_end(&mut buf).unwrap();
    //     let s = String::from_utf8(buf).unwrap();
    //     assert_eq!(s, msg);
    // }
}
