// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! NTAG213/215/216 configuration page parsing.
//!
//! The configuration pages (CFG0 and CFG1) control mirror features,
//! password protection, and NFC counter behavior.

/// Mirror mode (MIRROR_CONF field, CFG0 byte 0, bits 7:6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorMode {
    /// No ASCII mirror.
    None,
    /// UID ASCII mirror (14 bytes).
    Uid,
    /// NFC counter ASCII mirror (6 bytes).
    Counter,
    /// UID + NFC counter ASCII mirror (21 bytes, separated by 'x').
    UidAndCounter,
}

/// CFG0 page: mirror configuration and AUTH0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorConfig {
    /// Mirror mode.
    pub mirror_conf: MirrorMode,
    /// Byte position within the mirror page (0–3).
    pub mirror_byte: u8,
    /// Strong modulation mode enable.
    pub strg_mod_en: bool,
    /// Page where the ASCII mirror starts.
    pub mirror_page: u8,
    /// First page requiring password authentication (0xFF = disabled).
    pub auth0: u8,
}

impl MirrorConfig {
    /// Parse from CFG0 page (4 bytes).
    pub fn from_cfg0(bytes: [u8; 4]) -> Self {
        let mirror_conf = match (bytes[0] >> 6) & 0x03 {
            0 => MirrorMode::None,
            1 => MirrorMode::Uid,
            2 => MirrorMode::Counter,
            _ => MirrorMode::UidAndCounter,
        };
        MirrorConfig {
            mirror_conf,
            mirror_byte: (bytes[0] >> 4) & 0x03,
            strg_mod_en: bytes[0] & 0x08 != 0,
            mirror_page: bytes[2],
            auth0: bytes[3],
        }
    }

    /// Serialize to CFG0 page bytes.
    pub fn to_cfg0(&self) -> [u8; 4] {
        let conf_bits = match self.mirror_conf {
            MirrorMode::None => 0,
            MirrorMode::Uid => 1,
            MirrorMode::Counter => 2,
            MirrorMode::UidAndCounter => 3,
        };
        let byte0 = (conf_bits << 6)
            | ((self.mirror_byte & 0x03) << 4)
            | if self.strg_mod_en { 0x08 } else { 0 };
        [byte0, 0x00, self.mirror_page, self.auth0]
    }
}

/// CFG1 page: access control configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessConfig {
    /// Protection mode: false = write-only protection, true = read+write protection.
    pub prot: bool,
    /// Configuration lock: true = config pages locked after next power cycle.
    pub cfg_lck: bool,
    /// NFC counter enabled.
    pub nfc_cnt_en: bool,
    /// NFC counter password protected.
    pub nfc_cnt_pwd_prot: bool,
    /// Authentication limit (0 = unlimited, 1–7 = max failed attempts).
    pub authlim: u8,
}

impl AccessConfig {
    /// Parse from CFG1 page (4 bytes).
    pub fn from_cfg1(bytes: [u8; 4]) -> Self {
        AccessConfig {
            prot: bytes[0] & 0x80 != 0,
            cfg_lck: bytes[0] & 0x40 != 0,
            nfc_cnt_en: bytes[0] & 0x10 != 0,
            nfc_cnt_pwd_prot: bytes[0] & 0x08 != 0,
            authlim: bytes[0] & 0x07,
        }
    }

    /// Serialize to CFG1 page bytes.
    pub fn to_cfg1(&self) -> [u8; 4] {
        let byte0 = if self.prot { 0x80 } else { 0 }
            | if self.cfg_lck { 0x40 } else { 0 }
            | if self.nfc_cnt_en { 0x10 } else { 0 }
            | if self.nfc_cnt_pwd_prot { 0x08 } else { 0 }
            | (self.authlim & 0x07);
        [byte0, 0x00, 0x00, 0x00]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_mirror_config() {
        // Default CFG0: STRG_MOD_EN=1, everything else 0, AUTH0=0xFF
        let cfg = MirrorConfig::from_cfg0([0x08, 0x00, 0x00, 0xFF]);
        assert_eq!(cfg.mirror_conf, MirrorMode::None);
        assert_eq!(cfg.mirror_byte, 0);
        assert!(cfg.strg_mod_en);
        assert_eq!(cfg.mirror_page, 0);
        assert_eq!(cfg.auth0, 0xFF);
    }

    #[test]
    fn parse_uid_mirror() {
        let cfg = MirrorConfig::from_cfg0([0x48, 0x00, 0x10, 0xFF]);
        assert_eq!(cfg.mirror_conf, MirrorMode::Uid);
        assert_eq!(cfg.mirror_byte, 0);
        assert_eq!(cfg.mirror_page, 0x10);
    }

    #[test]
    fn roundtrip_mirror_config() {
        let cfg = MirrorConfig {
            mirror_conf: MirrorMode::UidAndCounter,
            mirror_byte: 2,
            strg_mod_en: true,
            mirror_page: 0x20,
            auth0: 0x10,
        };
        let bytes = cfg.to_cfg0();
        let parsed = MirrorConfig::from_cfg0(bytes);
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn parse_default_access_config() {
        // Default CFG1: NFC_CNT_EN=0, AUTHLIM=0, everything disabled
        let cfg = AccessConfig::from_cfg1([0x00, 0x00, 0x00, 0x00]);
        assert!(!cfg.prot);
        assert!(!cfg.cfg_lck);
        assert!(!cfg.nfc_cnt_en);
        assert!(!cfg.nfc_cnt_pwd_prot);
        assert_eq!(cfg.authlim, 0);
    }

    #[test]
    fn parse_protected_config() {
        // PROT=1, NFC_CNT_EN=1, AUTHLIM=3
        let cfg = AccessConfig::from_cfg1([0x93, 0x00, 0x00, 0x00]);
        assert!(cfg.prot);
        assert!(cfg.nfc_cnt_en);
        assert_eq!(cfg.authlim, 3);
    }

    #[test]
    fn roundtrip_access_config() {
        let cfg = AccessConfig {
            prot: true,
            cfg_lck: false,
            nfc_cnt_en: true,
            nfc_cnt_pwd_prot: true,
            authlim: 5,
        };
        let bytes = cfg.to_cfg1();
        let parsed = AccessConfig::from_cfg1(bytes);
        assert_eq!(parsed, cfg);
    }
}
