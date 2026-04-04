// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! GET_VERSION response parsing and NTAG variant identification.

use nfc_forum_tags::type2::Type2Error;

/// NTAG chip variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// NTAG213: 144 bytes user memory (pages 4–39), 45 pages total.
    Ntag213,
    /// NTAG215: 504 bytes user memory (pages 4–129), 135 pages total.
    Ntag215,
    /// NTAG216: 888 bytes user memory (pages 4–225), 231 pages total.
    Ntag216,
}

impl Variant {
    /// First user memory page (always page 4 for NTAG21x).
    pub fn first_user_page(self) -> u8 {
        4
    }

    /// Number of user memory pages.
    pub fn user_pages(self) -> u8 {
        match self {
            Variant::Ntag213 => 36,  // pages 4–39
            Variant::Ntag215 => 126, // pages 4–129
            Variant::Ntag216 => 222, // pages 4–225
        }
    }

    /// Total number of pages (including UID, CC, config, etc.).
    pub fn total_pages(self) -> u8 {
        match self {
            Variant::Ntag213 => 45,  // pages 0–44
            Variant::Ntag215 => 135, // pages 0–134
            Variant::Ntag216 => 231, // pages 0–230
        }
    }

    /// Last valid page address.
    pub fn last_page(self) -> u8 {
        self.total_pages() - 1
    }

    /// Page address of the dynamic lock bytes.
    pub fn dynamic_lock_page(self) -> u8 {
        match self {
            Variant::Ntag213 => 0x28,
            Variant::Ntag215 => 0x82,
            Variant::Ntag216 => 0xE2,
        }
    }

    /// Page address of CFG0 (MIRROR, RFUI, MIRROR_PAGE, AUTH0).
    pub fn cfg0_page(self) -> u8 {
        match self {
            Variant::Ntag213 => 0x29,
            Variant::Ntag215 => 0x83,
            Variant::Ntag216 => 0xE3,
        }
    }

    /// Page address of CFG1 (ACCESS, RFUI, RFUI, RFUI).
    pub fn cfg1_page(self) -> u8 {
        match self {
            Variant::Ntag213 => 0x2A,
            Variant::Ntag215 => 0x84,
            Variant::Ntag216 => 0xE4,
        }
    }

    /// Page address of the PWD (4-byte password).
    pub fn pwd_page(self) -> u8 {
        match self {
            Variant::Ntag213 => 0x2B,
            Variant::Ntag215 => 0x85,
            Variant::Ntag216 => 0xE5,
        }
    }

    /// Page address of the PACK (2-byte password acknowledge).
    pub fn pack_page(self) -> u8 {
        match self {
            Variant::Ntag213 => 0x2C,
            Variant::Ntag215 => 0x86,
            Variant::Ntag216 => 0xE6,
        }
    }
}

/// Parsed GET_VERSION response (8 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    /// Fixed header (0x00).
    pub header: u8,
    /// Vendor ID (0x04 = NXP Semiconductors).
    pub vendor: u8,
    /// Product type (0x04 = NTAG).
    pub product_type: u8,
    /// Product subtype (0x02 = 50 pF).
    pub product_subtype: u8,
    /// Major product version.
    pub major_version: u8,
    /// Minor product version.
    pub minor_version: u8,
    /// Storage size byte. Upper 7 bits encode 2^n range, LSB indicates exact/range.
    pub storage_size: u8,
    /// Protocol type (0x03 = ISO/IEC 14443-3 compliant).
    pub protocol_type: u8,
}

impl VersionInfo {
    /// Determine the NTAG variant from the storage size byte.
    ///
    /// Returns `None` if the storage size doesn't match a known variant.
    pub fn variant(&self) -> Option<Variant> {
        match self.storage_size {
            0x0F => Some(Variant::Ntag213),
            0x11 => Some(Variant::Ntag215),
            0x13 => Some(Variant::Ntag216),
            _ => None,
        }
    }

    /// Whether this is an NXP NTAG product.
    pub fn is_ntag(&self) -> bool {
        self.vendor == 0x04 && self.product_type == 0x04
    }
}

impl TryFrom<&[u8]> for VersionInfo {
    type Error = Type2Error;

    fn try_from(raw: &[u8]) -> Result<Self, Type2Error> {
        if raw.len() < 8 {
            return Err(Type2Error::InvalidLength);
        }
        Ok(VersionInfo {
            header: raw[0],
            vendor: raw[1],
            product_type: raw[2],
            product_subtype: raw[3],
            major_version: raw[4],
            minor_version: raw[5],
            storage_size: raw[6],
            protocol_type: raw[7],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ntag216_version() {
        let raw = [0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x13, 0x03];
        let info = VersionInfo::try_from(&raw[..]).unwrap();
        assert_eq!(info.variant(), Some(Variant::Ntag216));
        assert!(info.is_ntag());
    }

    #[test]
    fn parse_ntag215_version() {
        let raw = [0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03];
        let info = VersionInfo::try_from(&raw[..]).unwrap();
        assert_eq!(info.variant(), Some(Variant::Ntag215));
    }

    #[test]
    fn parse_ntag213_version() {
        let raw = [0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03];
        let info = VersionInfo::try_from(&raw[..]).unwrap();
        assert_eq!(info.variant(), Some(Variant::Ntag213));
    }

    #[test]
    fn unknown_storage_size() {
        let raw = [0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x20, 0x03];
        let info = VersionInfo::try_from(&raw[..]).unwrap();
        assert_eq!(info.variant(), None);
    }

    #[test]
    fn too_short_response() {
        let raw = [0x00, 0x04, 0x04];
        assert_eq!(
            VersionInfo::try_from(&raw[..]),
            Err(Type2Error::InvalidLength)
        );
    }

    #[test]
    fn variant_page_addresses() {
        assert_eq!(Variant::Ntag213.cfg0_page(), 0x29);
        assert_eq!(Variant::Ntag215.pwd_page(), 0x85);
        assert_eq!(Variant::Ntag216.pack_page(), 0xE6);
        assert_eq!(Variant::Ntag216.last_page(), 230);
    }
}
