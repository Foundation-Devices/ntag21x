// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! # ntag21x
//!
//! Driver for NXP NTAG213, NTAG215, and NTAG216 NFC tags.
//!
//! Extends the generic NFC Forum Type 2 Tag operations from
//! [`nfc_forum_tags`] with NTAG-specific commands:
//!
//! - [`NtagReader::get_version`] — chip identification
//! - [`NtagReader::fast_read`] — bulk page reads
//! - [`NtagReader::read_cnt`] — NFC counter
//! - [`NtagReader::pwd_auth`] — password authentication
//! - [`NtagReader::read_sig`] — ECC originality signature
//! - [`NtagReader::compatibility_write`] — MIFARE Classic compatible write
//!
//! All standard T2T operations (READ, WRITE, SECTOR SELECT, NDEF
//! read/write) are delegated to the underlying [`T2TReader`].

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod command;
pub mod config;
pub mod version;

pub use config::{AccessConfig, MirrorConfig, MirrorMode};
pub use version::{Variant, VersionInfo};

use nfc_forum_tags::type2::{ReaderError, T2TReader, T2TTransceiver, Type2Error};
use nfc_forum_tags::vec::DataVec;

/// NTAG213/215/216 reader/writer.
///
/// Wraps a [`T2TReader`] and adds NTAG-specific commands. All standard
/// T2T operations are available through delegation.
pub struct NtagReader<'t, T: T2TTransceiver<N>, const N: usize> {
    inner: T2TReader<'t, T, N>,
}

impl<'t, T: T2TTransceiver<N>, const N: usize> NtagReader<'t, T, N> {
    /// Create a new NTAG reader from a transceiver.
    pub fn new(transceiver: &'t mut T) -> Self {
        NtagReader {
            inner: T2TReader::new(transceiver),
        }
    }

    /// Access the underlying T2TReader.
    pub fn inner(&self) -> &T2TReader<'t, T, N> {
        &self.inner
    }

    /// Mutably access the underlying T2TReader.
    pub fn inner_mut(&mut self) -> &mut T2TReader<'t, T, N> {
        &mut self.inner
    }

    // ── Delegated T2T operations ───────────────────────────────────

    /// Read 4 blocks (16 bytes) starting at `block_no`.
    pub fn read(&mut self, block_no: u8) -> Result<[u8; 16], ReaderError<T::Error>> {
        self.inner.read(block_no)
    }

    /// Write 4 bytes to `block_no`.
    pub fn write(&mut self, block_no: u8, data: [u8; 4]) -> Result<(), ReaderError<T::Error>> {
        self.inner.write(block_no, data)
    }

    /// Select a sector (for tags > 1 KB).
    pub fn sector_select(&mut self, sector: u8) -> Result<(), ReaderError<T::Error>> {
        self.inner.sector_select(sector)
    }

    /// Read and parse the Capability Container.
    pub fn read_cc(
        &mut self,
    ) -> Result<nfc_forum_tags::type2::CapabilityContainer, ReaderError<T::Error>> {
        self.inner.read_cc()
    }

    /// Read the NDEF message bytes from the tag.
    pub fn read_ndef(&mut self) -> Result<DataVec, ReaderError<T::Error>> {
        self.inner.read_ndef()
    }

    /// Write NDEF message bytes to the tag.
    pub fn write_ndef(&mut self, ndef_data: &[u8]) -> Result<(), ReaderError<T::Error>> {
        self.inner.write_ndef(ndef_data)
    }

    /// Set the maximum number of retries on transient transceiver errors.
    pub fn set_max_retries(&mut self, n: u8) {
        self.inner.set_max_retries(n);
    }

    // ── FAST_READ-based alternatives ───────────────────────────────

    /// Read the NDEF message using a targeted FAST_READ.
    ///
    /// 1. READ block 4 to parse the TLV header and discover the NDEF
    ///    Message TLV length (T + L)
    /// 2. FAST_READ only the pages covering the NDEF payload (V)
    ///
    /// This typically requires just 2 RF transactions (1 READ + 1
    /// FAST_READ) regardless of NDEF size, compared to many READs in
    /// [`read_ndef`](Self::read_ndef). The CC is read first for
    /// validation (often a cache hit from a prior operation).
    pub fn read_ndef_fast(&mut self, variant: Variant) -> Result<DataVec, ReaderError<T::Error>> {
        let cc = self.read_cc()?;
        if !cc.is_valid() {
            return Err(Type2Error::InvalidMagic(0).into());
        }

        // READ block 4 (pages 4–7, 16 bytes) to scan for the NDEF TLV
        // header. This covers Lock/Memory Control TLVs and the start of
        // the NDEF data on most tags. The read cache makes this free if
        // read_cc already fetched overlapping blocks.
        let first_data = self.read(4)?;

        // Scan TLVs in these 16 bytes to find the NDEF Message TLV.
        let mut offset = 0usize;
        loop {
            if offset >= first_data.len() {
                return Ok(DataVec::new());
            }
            let tag = first_data[offset];
            offset += 1;
            match tag {
                0x00 => continue,                  // NULL TLV
                0xFE => return Ok(DataVec::new()), // Terminator
                0x03 => break,                     // NDEF Message TLV
                _ => {
                    // Skip unknown/control TLV: read L, advance past V.
                    if offset >= first_data.len() {
                        return Err(Type2Error::InvalidTlv.into());
                    }
                    if first_data[offset] == 0xFF {
                        if offset + 3 > first_data.len() {
                            return Err(Type2Error::InvalidTlv.into());
                        }
                        let len =
                            u16::from_be_bytes([first_data[offset + 1], first_data[offset + 2]]);
                        offset += 3 + len as usize;
                    } else {
                        offset += 1 + first_data[offset] as usize;
                    }
                }
            }
        }

        // Parse the L field of the NDEF Message TLV.
        if offset >= first_data.len() {
            return Err(Type2Error::InvalidTlv.into());
        }
        let (ndef_len, l_size) = if first_data[offset] == 0xFF {
            if offset + 3 > first_data.len() {
                return Err(Type2Error::InvalidTlv.into());
            }
            let len = u16::from_be_bytes([first_data[offset + 1], first_data[offset + 2]]);
            (len, 3usize)
        } else {
            (first_data[offset] as u16, 1usize)
        };

        if ndef_len == 0 {
            return Ok(DataVec::new()); // INITIALIZED state
        }

        // Compute the absolute byte range of the NDEF V field.
        let v_start_byte = 4 * 4 + offset + l_size; // page 4 base + TLV offset + L size
        let v_end_byte = v_start_byte + ndef_len as usize - 1;
        let start_page = (v_start_byte / 4) as u8;
        let end_page = (v_end_byte / 4) as u8;

        let last_user = variant.first_user_page() + variant.user_pages() - 1;
        if end_page > last_user {
            return Err(Type2Error::OutOfRange.into());
        }

        // FAST_READ only the pages containing the NDEF data.
        let raw = self.fast_read(start_page, end_page)?;

        // Extract just the NDEF bytes (skip page-alignment padding).
        let skip = v_start_byte - start_page as usize * 4;
        let mut result = DataVec::new();
        nfc_forum_tags::vec::VecExt::try_extend(&mut result, &raw[skip..skip + ndef_len as usize])
            .map_err(|_| Type2Error::BufferFull)?;
        Ok(result)
    }

    // ── NTAG-specific commands ─────────────────────────────────────

    /// GET_VERSION: retrieve chip identification (8 bytes).
    ///
    /// Returns a [`VersionInfo`] with vendor, product type, storage size,
    /// and protocol info. Use [`VersionInfo::variant()`] to determine
    /// NTAG213/215/216.
    pub fn get_version(&mut self) -> Result<VersionInfo, ReaderError<T::Error>> {
        let raw = self
            .inner
            .transceive_with_retry(&[command::CMD_GET_VERSION])?;
        VersionInfo::try_from(raw.as_slice()).map_err(ReaderError::Protocol)
    }

    /// FAST_READ: read pages from `start` to `end` (inclusive) in one RF transaction.
    ///
    /// Returns `(end - start + 1) * 4` bytes. More efficient than
    /// multiple READ commands for bulk reads.
    ///
    /// The response must fit in the transceiver's frame buffer (const
    /// generic `N`). Under `no_std`, returns [`Type2Error::OutOfRange`]
    /// if the requested range exceeds `N` bytes.
    pub fn fast_read(&mut self, start: u8, end: u8) -> Result<DataVec, ReaderError<T::Error>> {
        if end < start {
            return Err(Type2Error::OutOfRange.into());
        }
        #[cfg(not(feature = "alloc"))]
        {
            let response_size = (end as usize - start as usize + 1) * 4;
            if response_size > N {
                return Err(Type2Error::OutOfRange.into());
            }
        }
        let raw = self
            .inner
            .transceive_with_retry(&[command::CMD_FAST_READ, start, end])?;
        let expected = (end as usize - start as usize + 1) * 4;
        if raw.len() < expected {
            return Err(Type2Error::InvalidLength.into());
        }
        let mut result = DataVec::new();
        nfc_forum_tags::vec::VecExt::try_extend(&mut result, &raw[..expected])
            .map_err(|_| Type2Error::BufferFull)?;
        Ok(result)
    }

    /// READ_CNT: read the 24-bit NFC counter.
    ///
    /// Returns the counter value (0–16,777,215). The counter auto-increments
    /// on the first READ or FAST_READ after each power-on. Must be enabled
    /// via the NFC_CNT_EN configuration bit.
    pub fn read_cnt(&mut self) -> Result<u32, ReaderError<T::Error>> {
        let raw = self
            .inner
            .transceive_with_retry(&[command::CMD_READ_CNT, 0x02])?;
        if raw.len() < 3 {
            return Err(Type2Error::InvalidLength.into());
        }
        // 3 bytes, LSB first.
        Ok(raw[0] as u32 | (raw[1] as u32) << 8 | (raw[2] as u32) << 16)
    }

    /// PWD_AUTH: authenticate with a 32-bit password.
    ///
    /// Returns the 2-byte PACK (Password ACKnowledge) on success.
    /// After successful authentication, password-protected pages
    /// become accessible until the next HALT or power loss.
    pub fn pwd_auth(&mut self, pwd: [u8; 4]) -> Result<[u8; 2], ReaderError<T::Error>> {
        let raw = self.inner.transceive_with_retry(&[
            command::CMD_PWD_AUTH,
            pwd[0],
            pwd[1],
            pwd[2],
            pwd[3],
        ])?;
        if raw.len() < 2 {
            return Err(Type2Error::InvalidLength.into());
        }
        Ok([raw[0], raw[1]])
    }

    /// READ_SIG: read the 32-byte ECC originality signature.
    ///
    /// The signature is programmed at chip production and can be verified
    /// with NXP's public key (secp128r1) to confirm chip authenticity.
    pub fn read_sig(&mut self) -> Result<[u8; 32], ReaderError<T::Error>> {
        let raw = self
            .inner
            .transceive_with_retry(&[command::CMD_READ_SIG, 0x00])?;
        if raw.len() < 32 {
            return Err(Type2Error::InvalidLength.into());
        }
        let mut sig = [0u8; 32];
        sig.copy_from_slice(&raw[..32]);
        Ok(sig)
    }

    /// COMPATIBILITY_WRITE: write 4 bytes using the MIFARE Classic
    /// compatible two-phase protocol.
    ///
    /// Phase 1 sends the command + address, phase 2 sends 16 bytes
    /// (only the first 4 are written, rest must be 0x00).
    pub fn compatibility_write(
        &mut self,
        addr: u8,
        data: [u8; 4],
    ) -> Result<(), ReaderError<T::Error>> {
        // Phase 1: [0xA0, addr] → ACK.
        let raw = self
            .inner
            .transceive_with_retry(&[command::CMD_COMPATIBILITY_WRITE, addr])?;
        let val = raw.first().copied().unwrap_or(0) & 0x0F;
        if val != nfc_forum_tags::type2::ACK {
            return Err(Type2Error::Nack(val).into());
        }

        // Phase 2: [data(4) + padding(12)] → ACK.
        let mut payload = [0u8; 16];
        payload[..4].copy_from_slice(&data);
        let raw = self.inner.transceive_with_retry(&payload)?;
        let val = raw.first().copied().unwrap_or(0) & 0x0F;
        if val != nfc_forum_tags::type2::ACK {
            return Err(Type2Error::Nack(val).into());
        }

        self.inner.invalidate_cache();
        Ok(())
    }

    // ── Configuration helpers ──────────────────────────────────────

    /// Read the configuration pages (CFG0 + CFG1) for the given variant.
    pub fn read_config(
        &mut self,
        variant: Variant,
    ) -> Result<(MirrorConfig, AccessConfig), ReaderError<T::Error>> {
        let cfg0_page = variant.cfg0_page();
        let data = self.read(cfg0_page)?;
        // data[0..4] = CFG0, data[4..8] = CFG1
        let mirror = MirrorConfig::from_cfg0([data[0], data[1], data[2], data[3]]);
        let access = AccessConfig::from_cfg1([data[4], data[5], data[6], data[7]]);
        Ok((mirror, access))
    }

    /// Read the AUTH0 value (first password-protected page) for the given variant.
    pub fn read_auth0(&mut self, variant: Variant) -> Result<u8, ReaderError<T::Error>> {
        let cfg0_page = variant.cfg0_page();
        let data = self.read(cfg0_page)?;
        Ok(data[3]) // AUTH0 is byte 3 of CFG0
    }

    /// Check if password protection is active.
    ///
    /// Returns `None` if protection is disabled (AUTH0 beyond last user
    /// page). Returns `Some(prot)` if enabled, where `prot` is `false`
    /// for write-only protection and `true` for read+write protection.
    pub fn is_protected(
        &mut self,
        variant: Variant,
    ) -> Result<Option<bool>, ReaderError<T::Error>> {
        let (mirror, access) = self.read_config(variant)?;
        let last_user = variant.first_user_page() + variant.user_pages() - 1;
        if mirror.auth0 <= last_user {
            Ok(Some(access.prot))
        } else {
            Ok(None)
        }
    }

    // ── Configuration write helpers ────────────────────────────────

    /// Write the mirror configuration (CFG0 page).
    ///
    /// This sets mirror mode, mirror page/byte, strong modulation, and
    /// AUTH0 in a single page write.
    pub fn write_mirror_config(
        &mut self,
        variant: Variant,
        config: &MirrorConfig,
    ) -> Result<(), ReaderError<T::Error>> {
        self.write(variant.cfg0_page(), config.to_cfg0())
    }

    /// Write the access configuration (CFG1 page).
    ///
    /// This sets PROT, CFGLCK, NFC_CNT_EN, NFC_CNT_PWD_PROT, and
    /// AUTHLIM in a single page write.
    pub fn write_access_config(
        &mut self,
        variant: Variant,
        config: &AccessConfig,
    ) -> Result<(), ReaderError<T::Error>> {
        self.write(variant.cfg1_page(), config.to_cfg1())
    }

    /// Set the 4-byte password.
    pub fn write_pwd(
        &mut self,
        variant: Variant,
        pwd: [u8; 4],
    ) -> Result<(), ReaderError<T::Error>> {
        self.write(variant.pwd_page(), pwd)
    }

    /// Set the 2-byte PACK (Password ACKnowledge).
    ///
    /// Bytes 2–3 of the PACK page are RFU and written as 0x00.
    pub fn write_pack(
        &mut self,
        variant: Variant,
        pack: [u8; 2],
    ) -> Result<(), ReaderError<T::Error>> {
        self.write(variant.pack_page(), [pack[0], pack[1], 0x00, 0x00])
    }

    /// Enable password protection starting at page `auth0`.
    ///
    /// Writes in safe order: PWD, PACK, CFG1 (PROT/AUTHLIM), then
    /// CFG0 (AUTH0 last — this activates protection).
    ///
    /// Set `read_write_protect` to `false` for write-only protection
    /// or `true` for read+write protection.
    pub fn enable_protection(
        &mut self,
        variant: Variant,
        auth0: u8,
        pwd: [u8; 4],
        pack: [u8; 2],
        read_write_protect: bool,
    ) -> Result<(), ReaderError<T::Error>> {
        // 1. Set password first (before protection is active).
        self.write_pwd(variant, pwd)?;

        // 2. Set PACK.
        self.write_pack(variant, pack)?;

        // 3. Set PROT bit in CFG1 (read current config to preserve other bits).
        let (_, mut access) = self.read_config(variant)?;
        access.prot = read_write_protect;
        self.write_access_config(variant, &access)?;

        // 4. Set AUTH0 in CFG0 last (activates protection).
        let (mut mirror, _) = self.read_config(variant)?;
        mirror.auth0 = auth0;
        self.write_mirror_config(variant, &mirror)?;

        Ok(())
    }

    /// Disable password protection.
    ///
    /// Sets AUTH0 to 0xFF, which places the protection boundary beyond
    /// any addressable page.
    pub fn disable_protection(&mut self, variant: Variant) -> Result<(), ReaderError<T::Error>> {
        let (mut mirror, _) = self.read_config(variant)?;
        mirror.auth0 = 0xFF;
        self.write_mirror_config(variant, &mirror)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nfc_forum_tags::type2::ACK;
    use nfc_forum_tags::vec::{FrameVec, VecExt};

    /// Mock transceiver for NTAG testing.
    struct MockNtagTransceiver {
        /// Flat memory (231 pages * 4 bytes = 924 bytes for NTAG216).
        memory: [u8; 924],
    }

    impl MockNtagTransceiver {
        fn new_ntag216() -> Self {
            let mut t = MockNtagTransceiver { memory: [0u8; 924] };
            // CC (page 3)
            t.memory[12] = 0xE1; // magic
            t.memory[13] = 0x10; // version 1.0
            t.memory[14] = 0x6D; // 872 bytes data area
            t.memory[15] = 0x00; // r/w access
            // NDEF Message TLV + Terminator (page 4)
            t.memory[16] = 0x03; // T
            t.memory[17] = 0x00; // L = 0
            t.memory[18] = 0xFE; // Terminator
            t
        }
    }

    /// Frame buffer size for tests: large enough for NTAG216 FAST_READ.
    const TEST_FRAME_SIZE: usize = 924;

    impl T2TTransceiver<TEST_FRAME_SIZE> for MockNtagTransceiver {
        type Error = ();

        fn transceive(&mut self, cmd: &[u8]) -> Result<FrameVec<TEST_FRAME_SIZE>, ()> {
            if cmd.is_empty() {
                return Err(());
            }

            match cmd[0] {
                // T2T READ
                0x30 => {
                    let block = cmd[1] as usize;
                    let start = block * 4;
                    let mut response = FrameVec::new();
                    let end = (start + 16).min(self.memory.len());
                    let _ = response.try_extend(&self.memory[start..end]);
                    while response.len() < 16 {
                        let _ = response.try_push(0);
                    }
                    Ok(response)
                }
                // T2T WRITE
                0xA2 => {
                    let block = cmd[1] as usize;
                    let start = block * 4;
                    if start + 4 <= self.memory.len() && cmd.len() >= 6 {
                        self.memory[start..start + 4].copy_from_slice(&cmd[2..6]);
                    }
                    let mut response = FrameVec::new();
                    let _ = response.try_push(ACK);
                    Ok(response)
                }
                // GET_VERSION
                0x60 => {
                    let mut response = FrameVec::new();
                    let _ = response.try_extend(&[0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x13, 0x03]);
                    Ok(response)
                }
                // FAST_READ
                0x3A => {
                    let start_page = cmd[1] as usize;
                    let end_page = cmd[2] as usize;
                    let mut response = FrameVec::new();
                    for page in start_page..=end_page {
                        let offset = page * 4;
                        let end = (offset + 4).min(self.memory.len());
                        if offset < self.memory.len() {
                            let _ = response.try_extend(&self.memory[offset..end]);
                        }
                    }
                    Ok(response)
                }
                // READ_CNT
                0x39 => {
                    let mut response = FrameVec::new();
                    // Return counter = 42 (0x00002A), LSB first.
                    let _ = response.try_extend(&[0x2A, 0x00, 0x00]);
                    Ok(response)
                }
                // PWD_AUTH
                0x1B => {
                    let mut response = FrameVec::new();
                    // Accept any password, return PACK = [0xAB, 0xCD].
                    let _ = response.try_extend(&[0xAB, 0xCD]);
                    Ok(response)
                }
                // READ_SIG
                0x3C => {
                    let mut response = FrameVec::new();
                    let _ = response.try_extend(&[0xAA; 20]);
                    // FrameVec is 20 bytes — we need a bigger response.
                    // For testing, return what fits.
                    Ok(response)
                }
                // COMPATIBILITY_WRITE phase 1
                0xA0 => {
                    let mut response = FrameVec::new();
                    let _ = response.try_push(ACK);
                    Ok(response)
                }
                _ => Err(()),
            }
        }

        fn transceive_no_response(&mut self, _cmd: &[u8]) -> Result<Option<u8>, ()> {
            Ok(None)
        }
    }

    #[test]
    fn get_version_ntag216() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        let mut reader = NtagReader::new(&mut mock);
        let version = reader.get_version().unwrap();
        assert_eq!(version.vendor, 0x04);
        assert_eq!(version.product_type, 0x04);
        assert_eq!(version.storage_size, 0x13);
        assert_eq!(version.variant(), Some(Variant::Ntag216));
    }

    #[test]
    fn fast_read_pages() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        // Write known data to pages 4-5.
        mock.memory[16..24].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        let mut reader = NtagReader::new(&mut mock);
        let data = reader.fast_read(4, 5).unwrap();
        assert_eq!(&*data, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    }

    #[test]
    fn fast_read_invalid_range() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        let mut reader = NtagReader::new(&mut mock);
        assert!(reader.fast_read(5, 4).is_err());
    }

    #[test]
    fn read_counter() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        let mut reader = NtagReader::new(&mut mock);
        let cnt = reader.read_cnt().unwrap();
        assert_eq!(cnt, 42);
    }

    #[test]
    fn pwd_auth_returns_pack() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        let mut reader = NtagReader::new(&mut mock);
        let pack = reader.pwd_auth([0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
        assert_eq!(pack, [0xAB, 0xCD]);
    }

    #[test]
    fn read_cc_delegation() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        let mut reader = NtagReader::new(&mut mock);
        let cc = reader.read_cc().unwrap();
        assert_eq!(cc.version_major, 1);
        assert_eq!(cc.data_area_size(), 872);
    }

    #[test]
    fn read_ndef_delegation() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        let mut reader = NtagReader::new(&mut mock);
        let ndef = reader.read_ndef().unwrap();
        assert!(ndef.is_empty()); // INITIALIZED state
    }

    #[test]
    fn read_ndef_fast_empty() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        let mut reader = NtagReader::new(&mut mock);
        let ndef = reader.read_ndef_fast(Variant::Ntag216).unwrap();
        assert!(ndef.is_empty()); // INITIALIZED state
    }

    #[test]
    fn read_ndef_fast_with_data() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        // Write NDEF TLV with empty NDEF message D00000h.
        mock.memory[16] = 0x03; // T
        mock.memory[17] = 0x03; // L = 3
        mock.memory[18] = 0xD0; // V[0]
        mock.memory[19] = 0x00; // V[1]
        mock.memory[20] = 0x00; // V[2]
        mock.memory[21] = 0xFE; // Terminator
        let mut reader = NtagReader::new(&mut mock);
        let ndef = reader.read_ndef_fast(Variant::Ntag216).unwrap();
        assert_eq!(&*ndef, &[0xD0, 0x00, 0x00]);
    }

    #[test]
    fn is_protected_default_disabled() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        // Default CFG0: AUTH0 = 0xFF (disabled).
        let cfg0_addr = Variant::Ntag216.cfg0_page() as usize * 4;
        mock.memory[cfg0_addr] = 0x08; // STRG_MOD_EN
        mock.memory[cfg0_addr + 3] = 0xFF; // AUTH0
        let mut reader = NtagReader::new(&mut mock);
        assert_eq!(reader.is_protected(Variant::Ntag216).unwrap(), None);
    }

    #[test]
    fn is_protected_write_only() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        let cfg0_addr = Variant::Ntag216.cfg0_page() as usize * 4;
        mock.memory[cfg0_addr + 3] = 0x04; // AUTH0 = page 4
        let cfg1_addr = Variant::Ntag216.cfg1_page() as usize * 4;
        mock.memory[cfg1_addr] = 0x00; // PROT = 0 (write-only)
        let mut reader = NtagReader::new(&mut mock);
        assert_eq!(reader.is_protected(Variant::Ntag216).unwrap(), Some(false));
    }

    #[test]
    fn is_protected_read_write() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        let cfg0_addr = Variant::Ntag216.cfg0_page() as usize * 4;
        mock.memory[cfg0_addr + 3] = 0x04; // AUTH0 = page 4
        let cfg1_addr = Variant::Ntag216.cfg1_page() as usize * 4;
        mock.memory[cfg1_addr] = 0x80; // PROT = 1 (read+write)
        let mut reader = NtagReader::new(&mut mock);
        assert_eq!(reader.is_protected(Variant::Ntag216).unwrap(), Some(true));
    }

    #[test]
    fn enable_then_check_protection() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        // Set default config pages.
        let cfg0_addr = Variant::Ntag216.cfg0_page() as usize * 4;
        mock.memory[cfg0_addr] = 0x08; // STRG_MOD_EN
        mock.memory[cfg0_addr + 3] = 0xFF; // AUTH0 disabled
        let mut reader = NtagReader::new(&mut mock);

        // Enable write-only protection from page 0x10.
        reader
            .enable_protection(
                Variant::Ntag216,
                0x10,
                [0x11, 0x22, 0x33, 0x44],
                [0xAB, 0xCD],
                false,
            )
            .unwrap();

        // Verify protection is active.
        assert_eq!(reader.is_protected(Variant::Ntag216).unwrap(), Some(false));

        // Verify AUTH0 was written.
        assert_eq!(reader.read_auth0(Variant::Ntag216).unwrap(), 0x10);
    }

    #[test]
    fn disable_protection() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        let cfg0_addr = Variant::Ntag216.cfg0_page() as usize * 4;
        mock.memory[cfg0_addr] = 0x08;
        mock.memory[cfg0_addr + 3] = 0x10; // AUTH0 = 0x10 (enabled)
        let mut reader = NtagReader::new(&mut mock);

        reader.disable_protection(Variant::Ntag216).unwrap();

        assert_eq!(reader.is_protected(Variant::Ntag216).unwrap(), None);
        assert_eq!(reader.read_auth0(Variant::Ntag216).unwrap(), 0xFF);
    }

    #[test]
    fn write_pwd_and_pack() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        let mut reader = NtagReader::new(&mut mock);

        reader
            .write_pwd(Variant::Ntag216, [0xDE, 0xAD, 0xBE, 0xEF])
            .unwrap();
        reader.write_pack(Variant::Ntag216, [0x12, 0x34]).unwrap();

        // Verify in mock memory.
        let pwd_addr = Variant::Ntag216.pwd_page() as usize * 4;
        assert_eq!(
            &mock.memory[pwd_addr..pwd_addr + 4],
            &[0xDE, 0xAD, 0xBE, 0xEF]
        );
        let pack_addr = Variant::Ntag216.pack_page() as usize * 4;
        assert_eq!(
            &mock.memory[pack_addr..pack_addr + 4],
            &[0x12, 0x34, 0x00, 0x00]
        );
    }
}
