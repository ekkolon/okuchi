use crate::Result;

/// A trait that enables incremental encryption/decryption.
pub trait Stream {
    fn update<D: AsRef<[u8]>>(&mut self, data: D) -> Result<Vec<u8>>;
    fn finalize(self) -> Result<Vec<u8>>;
}
