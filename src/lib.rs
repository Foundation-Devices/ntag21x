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
    ///
    /// Rejects payloads that cannot fit the tag's data area before
    /// delegating, so an oversized attacker-influenced buffer can never
    /// reach a page-write path — a defense-in-depth guard against
    /// overwriting the dynamic-lock, configuration, PWD, and PACK pages
    /// (SFT-7601) that holds even if linked against an unfixed
    /// `nfc-forum-tags`. The CC read here is served from the reader cache
    /// by the delegated call, so it costs no extra RF traffic.
    pub fn write_ndef(&mut self, ndef_data: &[u8]) -> Result<(), ReaderError<T::Error>> {
        let cc = self.inner.read_cc()?;
        // Largest possible payload is the data area minus the minimal TLV
        // framing (T + 1-byte L + Terminator = 3 bytes). This is a loose
        // upper bound; the underlying writer performs the exact,
        // offset-aware capacity check.
        let max_payload = cc.data_area_size().saturating_sub(3) as usize;
        if ndef_data.len() > max_payload {
            return Err(Type2Error::OutOfRange.into());
        }
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

        // Compute the absolute byte range of the NDEF V field. All page and
        // byte math stays in usize so an attacker-chosen extended length
        // cannot wrap a `u8` page number into a small in-range value and
        // slip a short FAST_READ past the bounds check below.
        let ndef_len = ndef_len as usize;
        let v_start_byte = 4 * 4 + offset + l_size; // page 4 base + TLV offset + L size
        let v_end_byte = v_start_byte + ndef_len - 1;
        let start_page_wide = v_start_byte / 4;
        let end_page_wide = v_end_byte / 4;

        // Prove the whole value range fits both boundaries before narrowing
        // any page number to u8:
        //   1. the selected variant's user-memory pages, and
        //   2. the Capability Container data area (which can be smaller than
        //      physical user memory), whose bytes begin at page 4.
        let last_user_page = variant.first_user_page() as usize + variant.user_pages() as usize - 1;
        let data_area_end_byte = 4 * 4 + cc.data_area_size() as usize;
        if end_page_wide > last_user_page || v_end_byte >= data_area_end_byte {
            return Err(Type2Error::OutOfRange.into());
        }

        // Narrow to u8 only after the range is proven in bounds. Fallible
        // conversion keeps this safe even if the boundaries above ever change.
        let start_page = u8::try_from(start_page_wide).map_err(|_| Type2Error::OutOfRange)?;
        let end_page = u8::try_from(end_page_wide).map_err(|_| Type2Error::OutOfRange)?;

        // FAST_READ only the pages containing the NDEF data.
        let raw = self.fast_read(start_page, end_page)?;

        // Extract just the NDEF bytes (skip page-alignment padding). Prove the
        // response actually contains the full slice before indexing, so a
        // short frame yields a typed error instead of a panic.
        let skip = v_start_byte - start_page as usize * 4;
        let slice_end = skip + ndef_len;
        if raw.len() < slice_end {
            return Err(Type2Error::InvalidLength.into());
        }
        let mut result = DataVec::new();
        nfc_forum_tags::vec::VecExt::try_extend(&mut result, &raw[skip..slice_end])
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
    ///
    /// # Ambiguous outcomes
    ///
    /// Phase 2 is sent **exactly once** and is never retried. Its 16 bytes are
    /// data only while the tag is in data state; once the tag has returned to
    /// command state the same bytes parse as a fresh command, so replaying a
    /// payload that begins with, say, `0xA2` would execute an unintended WRITE
    /// to an attacker-chosen page.
    ///
    /// If phase 2 fails in transport, the tag may or may not have committed the
    /// write. This returns [`Type2Error::AmbiguousOutcome`] and marks the tag
    /// state unknown. Recover by reactivating the tag and reading back `addr`
    /// to determine what actually happened, before issuing any other
    /// state-changing command.
    pub fn compatibility_write(
        &mut self,
        addr: u8,
        data: [u8; 4],
    ) -> Result<(), ReaderError<T::Error>> {
        // Phase 1: [0xA0, addr] → ACK. This frame is sent in command state and
        // changes no memory, so the generic retry is safe here.
        let raw = self
            .inner
            .transceive_with_retry(&[command::CMD_COMPATIBILITY_WRITE, addr])?;
        let val = raw.first().copied().unwrap_or(0) & 0x0F;
        if val != nfc_forum_tags::type2::ACK {
            return Err(Type2Error::Nack(val).into());
        }

        // Phase 2: [data(4) + padding(12)] → ACK. Sent once, bypassing the
        // retry helper (see the note above).
        let mut payload = [0u8; 16];
        payload[..4].copy_from_slice(&data);
        self.inner.invalidate_cache();
        let raw = match self.inner.transceiver().transceive(&payload) {
            Ok(raw) => raw,
            Err(_) => {
                // The tag may already have committed the write. Do not replay.
                self.inner.mark_tag_state_unknown();
                return Err(Type2Error::AmbiguousOutcome.into());
            }
        };
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

    // ── write_ndef bounds enforcement (SFT-7601) ───────────────────

    /// NTAG mock that applies writes to flat memory and counts every WRITE,
    /// with the security pages (dynamic lock, CFG0, CFG1, PWD, PACK) stamped
    /// with a sentinel so tests can prove they were never overwritten.
    struct RecordingNtag {
        memory: [u8; 924],
        writes: usize,
    }

    const SENTINEL: [u8; 4] = [0x99, 0x99, 0x99, 0x99];

    impl RecordingNtag {
        fn new(variant: Variant, size_field: u8) -> Self {
            let mut t = RecordingNtag {
                memory: [0u8; 924],
                writes: 0,
            };
            // CC (page 3).
            t.memory[12] = 0xE1; // magic
            t.memory[13] = 0x10; // version 1.0
            t.memory[14] = size_field; // data area = size_field * 8
            t.memory[15] = 0x00; // r/w access
            // Empty NDEF Message TLV + Terminator (page 4).
            t.memory[16] = 0x03;
            t.memory[17] = 0x00;
            t.memory[18] = 0xFE;
            // Stamp the security pages so any stray write is detectable.
            for page in t.security_pages(variant) {
                let a = page as usize * 4;
                t.memory[a..a + 4].copy_from_slice(&SENTINEL);
            }
            t
        }

        fn security_pages(&self, v: Variant) -> [u8; 5] {
            [
                v.dynamic_lock_page(),
                v.cfg0_page(),
                v.cfg1_page(),
                v.pwd_page(),
                v.pack_page(),
            ]
        }

        fn security_untouched(&self, v: Variant) -> bool {
            self.security_pages(v).iter().all(|&page| {
                let a = page as usize * 4;
                self.memory[a..a + 4] == SENTINEL
            })
        }
    }

    impl T2TTransceiver<TEST_FRAME_SIZE> for RecordingNtag {
        type Error = ();

        fn transceive(&mut self, cmd: &[u8]) -> Result<FrameVec<TEST_FRAME_SIZE>, ()> {
            match cmd.first().copied() {
                Some(0x30) => {
                    // READ
                    let start = cmd[1] as usize * 4;
                    let mut response = FrameVec::new();
                    let end = (start + 16).min(self.memory.len());
                    let _ = response.try_extend(&self.memory[start..end]);
                    while response.len() < 16 {
                        let _ = response.try_push(0);
                    }
                    Ok(response)
                }
                Some(0xA2) => {
                    // WRITE
                    self.writes += 1;
                    let start = cmd[1] as usize * 4;
                    if start + 4 <= self.memory.len() && cmd.len() >= 6 {
                        self.memory[start..start + 4].copy_from_slice(&cmd[2..6]);
                    }
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

    /// (variant, CC size field) for each supported NTAG.
    const VARIANTS: [(Variant, u8); 3] = [
        (Variant::Ntag213, 0x12), // 144-byte data area
        (Variant::Ntag215, 0x3E), // 496-byte data area
        (Variant::Ntag216, 0x6D), // 872-byte data area
    ];

    /// An oversized NDEF write (65,536 bytes) is rejected with a range error
    /// and issues zero writes, leaving the security pages intact.
    #[test]
    fn write_ndef_oversized_rejected_no_writes() {
        for (variant, size_field) in VARIANTS {
            let mut mock = RecordingNtag::new(variant, size_field);
            {
                let mut reader = NtagReader::new(&mut mock);
                let oversized = [0xAAu8; 65_536];
                let res = reader.write_ndef(&oversized);
                assert!(
                    matches!(res, Err(ReaderError::Protocol(Type2Error::OutOfRange))),
                    "{variant:?} should reject oversized input"
                );
            }
            assert_eq!(mock.writes, 0, "{variant:?} must not write any page");
            assert!(
                mock.security_untouched(variant),
                "{variant:?} security pages must be untouched"
            );
        }
    }

    /// The maximum valid payload for each variant is written successfully
    /// and never touches the dynamic-lock or configuration pages.
    #[test]
    fn write_ndef_max_payload_spares_security_pages() {
        // Big enough source buffer for the largest variant (872 - 3).
        let src = [0x5Au8; 869];
        for (variant, size_field) in VARIANTS {
            let mut mock = RecordingNtag::new(variant, size_field);
            let data_area = size_field as usize * 8;
            // Framing is T + L + Terminator: L is 1 byte for payloads up to
            // 0xFE, otherwise a 3-byte field. The largest payload that still
            // fits the data area therefore reserves 3 or 5 bytes of framing.
            let max_payload = if data_area - 3 <= 0xFE {
                data_area - 3
            } else {
                data_area - 5
            };
            {
                let mut reader = NtagReader::new(&mut mock);
                reader.write_ndef(&src[..max_payload]).unwrap();
            }
            assert!(
                mock.security_untouched(variant),
                "{variant:?} max payload must not reach security pages"
            );
            // Sanity: the NDEF TLV header was actually written.
            assert_eq!(mock.memory[16], 0x03, "{variant:?} NDEF T written");
        }
    }

    // ── read_ndef_fast malicious-length panic hardening (SFT-7599) ──

    const ALL_VARIANTS: [(Variant, u8); 3] = [
        (Variant::Ntag213, 0x12), // CC data area 144
        (Variant::Ntag215, 0x3E), // CC data area 496
        (Variant::Ntag216, 0x6D), // CC data area 872
    ];

    /// Build an NTAG216-sized mock with a valid CC for `size_field`, an
    /// optional run of NULL TLVs as an offset, and an extended-length NDEF
    /// Message TLV header (`03 FF hi lo`) declaring `ndef_len`. When `fill_v`,
    /// the value bytes are written as `i % 256` so the decoded slice can be
    /// checked byte for byte.
    fn setup_fast_tag(
        size_field: u8,
        null_prefix: usize,
        ndef_len: u16,
        fill_v: bool,
    ) -> MockNtagTransceiver {
        let mut t = MockNtagTransceiver { memory: [0u8; 924] };
        t.memory[12] = 0xE1; // magic
        t.memory[13] = 0x10; // version 1.0
        t.memory[14] = size_field; // CC data area = size_field * 8
        t.memory[15] = 0x00; // r/w access
        let hdr = 16 + null_prefix; // NULL TLVs (0x00) occupy the offset
        t.memory[hdr] = 0x03; // NDEF Message TLV
        t.memory[hdr + 1] = 0xFF; // 3-byte length marker
        t.memory[hdr + 2] = (ndef_len >> 8) as u8;
        t.memory[hdr + 3] = ndef_len as u8;
        if fill_v {
            let v = hdr + 4;
            for i in 0..ndef_len as usize {
                if v + i < t.memory.len() {
                    t.memory[v + i] = (i % 256) as u8;
                }
            }
        }
        t
    }

    /// The 1,028-byte proof header whose end page wraps a `u8` to a small
    /// in-range value must return a typed error, not panic, on every variant.
    #[test]
    fn read_ndef_fast_rejects_wrapping_length() {
        for (variant, size_field) in ALL_VARIANTS {
            let mut mock = setup_fast_tag(size_field, 0, 0x0404, false); // 1028
            let mut reader = NtagReader::new(&mut mock);
            let res = reader.read_ndef_fast(variant);
            assert!(
                matches!(res, Err(ReaderError::Protocol(Type2Error::OutOfRange))),
                "{variant:?}: expected OutOfRange, got {res:?}"
            );
        }
    }

    /// The same wrapping length behind a range of NULL-TLV offsets is still
    /// rejected without panic, covering non-zero NDEF TLV offsets.
    #[test]
    fn read_ndef_fast_rejects_wrapping_length_at_offsets() {
        for (variant, size_field) in ALL_VARIANTS {
            for null_prefix in 0usize..=8 {
                let mut mock = setup_fast_tag(size_field, null_prefix, 0x0404, false);
                let mut reader = NtagReader::new(&mut mock);
                let res = reader.read_ndef_fast(variant);
                assert!(
                    matches!(res, Err(ReaderError::Protocol(Type2Error::OutOfRange))),
                    "{variant:?} offset {null_prefix}: expected OutOfRange, got {res:?}"
                );
            }
        }
    }

    /// Exhaustively sweep every 16-bit extended length across all three
    /// variants: each call must return `Ok` or a typed error, never panic.
    #[test]
    fn read_ndef_fast_all_lengths_no_panic() {
        for (variant, size_field) in ALL_VARIANTS {
            let mut mock = setup_fast_tag(size_field, 0, 0, false);
            for len in 0u16..=u16::MAX {
                mock.memory[18] = (len >> 8) as u8;
                mock.memory[19] = len as u8;
                let mut reader = NtagReader::new(&mut mock);
                // The result is intentionally ignored; a panic fails the test.
                let _ = reader.read_ndef_fast(variant);
            }
        }
    }

    /// A valid maximum-sized NDEF for each variant reads back correctly.
    #[test]
    fn read_ndef_fast_max_valid_ndef_succeeds() {
        for (variant, size_field) in ALL_VARIANTS {
            let data_area = size_field as usize * 8;
            // Extended TLV header (4 bytes) starts the data area, so the
            // largest value ends exactly at the data-area boundary.
            let max_v = data_area - 4;
            let mut mock = setup_fast_tag(size_field, 0, max_v as u16, true);
            let mut reader = NtagReader::new(&mut mock);
            let ndef = reader.read_ndef_fast(variant).unwrap();
            assert_eq!(ndef.len(), max_v, "{variant:?} length");
            assert!(
                ndef.iter().enumerate().all(|(i, &b)| b == (i % 256) as u8),
                "{variant:?} value bytes mismatch"
            );
        }
    }

    // ── Malformed control TLVs via delegated reads (SFT-7603) ──────

    /// A malicious tag presenting the audit's Lock Control TLV
    /// `[01, 03, F0, 08, 1F]` (byte address 491,520 — past the last sector)
    /// must produce a typed `InvalidTlv` through the delegated `read_ndef`,
    /// not a panic in overflow-checked builds nor a wrapped, bogus layout.
    #[test]
    fn read_ndef_rejects_out_of_range_lock_control_tlv() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        // Dynamic CC so the layout path builds lock areas.
        mock.memory[12..16].copy_from_slice(&[0xE1, 0x10, 0x6D, 0x00]);
        // Lock Control TLV with the demonstrated out-of-range descriptor.
        mock.memory[16] = 0x01;
        mock.memory[17] = 0x03;
        mock.memory[18] = 0xF0;
        mock.memory[19] = 0x08;
        mock.memory[20] = 0x1F;
        mock.memory[21] = 0xFE; // Terminator

        let mut reader = NtagReader::new(&mut mock);
        let res = reader.read_ndef();
        assert!(
            matches!(res, Err(ReaderError::Protocol(Type2Error::InvalidTlv))),
            "expected InvalidTlv, got {res:?}"
        );
    }

    /// The same shape with a Memory Control TLV is rejected identically.
    #[test]
    fn read_ndef_rejects_out_of_range_memory_control_tlv() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        mock.memory[12..16].copy_from_slice(&[0xE1, 0x10, 0x6D, 0x00]);
        mock.memory[16] = 0x02; // Memory Control
        mock.memory[17] = 0x03;
        mock.memory[18] = 0xF0; // page 15
        mock.memory[19] = 0x08; // size 8
        mock.memory[20] = 0x0F; // bytes_per_page = 15 → 491,520
        mock.memory[21] = 0xFE;

        let mut reader = NtagReader::new(&mut mock);
        assert!(matches!(
            reader.read_ndef(),
            Err(ReaderError::Protocol(Type2Error::InvalidTlv))
        ));
    }

    /// A tag with a legitimate in-range control TLV still reads normally, so
    /// the validation does not break valid dynamic tags.
    #[test]
    fn read_ndef_accepts_in_range_control_tlv() {
        let mut mock = MockNtagTransceiver::new_ntag216();
        mock.memory[12..16].copy_from_slice(&[0xE1, 0x10, 0x6D, 0x00]);
        mock.memory[16] = 0x01; // Lock Control
        mock.memory[17] = 0x03;
        mock.memory[18] = 0xE0; // page 14, offset 0
        mock.memory[19] = 0x06; // 6 lock bits
        mock.memory[20] = 0x33; // locked_per_bit=3, bytes_per_page=3 → addr 112
        mock.memory[21] = 0x03; // NDEF Message TLV
        mock.memory[22] = 0x03; // L = 3
        mock.memory[23] = 0xD0;
        mock.memory[24] = 0x00;
        mock.memory[25] = 0x00;
        mock.memory[26] = 0xFE;

        let mut reader = NtagReader::new(&mut mock);
        let ndef = reader.read_ndef().unwrap();
        assert_eq!(&*ndef, &[0xD0, 0x00, 0x00]);
    }

    // ── COMPATIBILITY_WRITE replay safety (SFT-7600) ───────────────

    /// Models the dangerous boundary: the tag commits phase 2, then the
    /// acknowledgement is lost so the transceiver reports an error. Any
    /// retransmission arrives in *command* state, where the payload's first
    /// bytes would be parsed as a new command. Records every frame so the test
    /// can prove the payload was sent only once and no second command ran.
    struct LostAckTransceiver {
        memory: [u8; 924],
        /// Every frame the reader transmitted, in order.
        frames: heapless::Vec<heapless::Vec<u8, 16>, 8>,
        /// True once phase 1 has been acknowledged (tag is in data state).
        in_data_state: bool,
        /// Pages written as a result of a frame parsed in command state.
        command_state_writes: heapless::Vec<u8, 8>,
        /// When true, phase 2 commits but its acknowledgement is lost.
        lose_ack: bool,
        /// Address captured from phase 1.
        pending_addr: u8,
    }

    impl LostAckTransceiver {
        fn new() -> Self {
            LostAckTransceiver {
                memory: [0u8; 924],
                frames: heapless::Vec::new(),
                in_data_state: false,
                command_state_writes: heapless::Vec::new(),
                lose_ack: true,
                pending_addr: 0,
            }
        }
    }

    impl T2TTransceiver<TEST_FRAME_SIZE> for LostAckTransceiver {
        type Error = ();

        fn transceive(&mut self, cmd: &[u8]) -> Result<FrameVec<TEST_FRAME_SIZE>, ()> {
            let mut rec = heapless::Vec::<u8, 16>::new();
            let _ = rec.extend_from_slice(&cmd[..cmd.len().min(16)]);
            let _ = self.frames.push(rec);

            if self.in_data_state {
                // Phase 2 payload: commit the intended write to the address
                // captured in phase 1, then either lose the ACK or return it.
                self.in_data_state = false;
                let start = self.pending_addr as usize * 4;
                if start + 4 <= self.memory.len() && cmd.len() >= 4 {
                    self.memory[start..start + 4].copy_from_slice(&cmd[..4]);
                }
                if self.lose_ack {
                    return Err(());
                }
                let mut response = FrameVec::new();
                let _ = response.try_push(ACK);
                return Ok(response);
            }

            match cmd.first().copied() {
                // Phase 1 of COMPATIBILITY_WRITE: enter data state.
                Some(0xA0) => {
                    self.in_data_state = true;
                    self.pending_addr = cmd[1];
                    let mut response = FrameVec::new();
                    let _ = response.try_push(ACK);
                    Ok(response)
                }
                // A WRITE parsed in command state — exactly what a replayed
                // payload beginning 0xA2 would become.
                Some(0xA2) => {
                    let _ = self.command_state_writes.push(cmd[1]);
                    let start = cmd[1] as usize * 4;
                    if start + 4 <= self.memory.len() && cmd.len() >= 6 {
                        self.memory[start..start + 4].copy_from_slice(&cmd[2..6]);
                    }
                    let mut response = FrameVec::new();
                    let _ = response.try_push(ACK);
                    Ok(response)
                }
                Some(0x30) => {
                    let mut response = FrameVec::new();
                    let _ = response.try_extend(&[0u8; 16]);
                    Ok(response)
                }
                _ => Err(()),
            }
        }

        fn transceive_no_response(&mut self, _cmd: &[u8]) -> Result<Option<u8>, ()> {
            Ok(None)
        }
    }

    /// A lost acknowledgement after commit must produce exactly one 16-byte
    /// transmission, an ambiguous-outcome error, and no second command — even
    /// when the payload's leading bytes form a valid WRITE to a security page.
    #[test]
    fn compatibility_write_never_replays_phase_two() {
        // 0xA2 = WRITE, 0x2A = NTAG213 CFG1 page: a replay would reconfigure
        // access protection.
        for payload in [
            [0xA2, 0x2A, 0xC0, 0x00],
            [0xA0, 0x2B, 0x11, 0x22],
            [0x30, 0x04, 0x00, 0x00],
        ] {
            let mut mock = LostAckTransceiver::new();
            {
                let mut reader = NtagReader::new(&mut mock);
                reader.set_max_retries(3); // retries must not apply to phase 2
                let res = reader.compatibility_write(0x04, payload);
                assert!(
                    matches!(
                        res,
                        Err(ReaderError::Protocol(Type2Error::AmbiguousOutcome))
                    ),
                    "payload {payload:02X?} should report an ambiguous outcome, got {res:?}"
                );
            }
            // Frame 1 is phase 1 (2 bytes); frame 2 is the single phase-2
            // payload. Nothing after it.
            assert_eq!(
                mock.frames.len(),
                2,
                "payload {payload:02X?}: expected exactly one phase-2 transmission"
            );
            assert_eq!(mock.frames[1].len(), 16);
            assert!(
                mock.command_state_writes.is_empty(),
                "payload {payload:02X?}: no command may execute from a replay"
            );
        }
    }

    /// After an ambiguous phase 2, the reader's sector state is unknown so the
    /// caller cannot proceed on stale assumptions.
    #[test]
    fn compatibility_write_ambiguity_marks_state_unknown() {
        let mut mock = LostAckTransceiver::new();
        let mut reader = NtagReader::new(&mut mock);
        assert!(
            reader
                .compatibility_write(0x04, [0xA2, 0x2A, 0xC0, 0x00])
                .is_err()
        );
        assert_eq!(reader.inner().current_sector(), None);
    }

    /// The success path still works: phase 2 acknowledged normally, the write
    /// lands on the requested page, and exactly two frames are sent.
    #[test]
    fn compatibility_write_success_path() {
        let mut mock = LostAckTransceiver::new();
        mock.lose_ack = false;
        {
            let mut reader = NtagReader::new(&mut mock);
            reader
                .compatibility_write(0x04, [0xDE, 0xAD, 0xBE, 0xEF])
                .unwrap();
        }
        assert_eq!(&mock.memory[16..20], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(mock.frames.len(), 2);
        assert!(mock.command_state_writes.is_empty());
    }
}
