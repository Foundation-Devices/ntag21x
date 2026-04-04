// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! NTAG213/215/216 command codes.
//!
//! These extend the NFC Forum Type 2 Tag command set with NXP
//! proprietary commands.

/// GET_VERSION command code.
pub const CMD_GET_VERSION: u8 = 0x60;

/// FAST_READ command code.
pub const CMD_FAST_READ: u8 = 0x3A;

/// READ_CNT command code.
pub const CMD_READ_CNT: u8 = 0x39;

/// PWD_AUTH command code.
pub const CMD_PWD_AUTH: u8 = 0x1B;

/// READ_SIG command code.
pub const CMD_READ_SIG: u8 = 0x3C;

/// COMPATIBILITY_WRITE command code.
pub const CMD_COMPATIBILITY_WRITE: u8 = 0xA0;
