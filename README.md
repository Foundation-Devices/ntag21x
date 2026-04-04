# ntag21x

`#![no_std]` Rust driver for NXP NTAG213, NTAG215, and NTAG216 NFC tags.

Extends the generic [nfc-forum-tags](../nfc-forum-tags) Type 2 Tag operations with NTAG-specific commands. All standard T2T operations (READ, WRITE, SECTOR SELECT, NDEF read/write) are delegated to the underlying `T2TReader`.

## Functionalities

### NTAG-Specific Commands

- **GET_VERSION** (0x60) — chip identification and variant detection (NTAG213/215/216)
- **FAST_READ** (0x3A) — bulk page reads in a single RF transaction
- **READ_CNT** (0x39) — read the 24-bit NFC counter
- **PWD_AUTH** (0x1B) — password authentication (returns 2-byte PACK)
- **READ_SIG** (0x3C) — read 32-byte ECC originality signature
- **COMPATIBILITY_WRITE** (0xA0) — MIFARE Classic compatible two-phase write

### Configuration

- Mirror configuration (UID/counter ASCII mirror)
- Access control (PROT, CFGLCK, NFC_CNT_EN, NFC_CNT_PWD_PROT, AUTHLIM)
- Per-variant page addresses (CFG0, CFG1, PWD, PACK, dynamic lock)

### FAST_READ-Optimized Operations

- **`read_ndef_fast`** — reads NDEF in 2 RF transactions: one READ to parse the TLV header (T+L), then a targeted FAST_READ of just the NDEF payload pages

### Delegated T2T Operations

- READ / WRITE / SECTOR SELECT
- Capability Container parsing
- NDEF detection, read, and write
- Persistent read cache and transceiver error retry

## Usage

```rust
use ntag21x::NtagReader;
use nfc_forum_tags::type2::T2TTransceiver;

// After ISO 14443-3A activation...
let mut reader = NtagReader::new(&mut my_transceiver);

// Identify the chip
let version = reader.get_version()?;
let variant = version.variant(); // Some(Ntag216)

// Bulk read pages 4–15 in one RF transaction
let data = reader.fast_read(4, 15)?;

// Read the NFC counter
let count = reader.read_cnt()?;

// Password authentication
let pack = reader.pwd_auth([0xFF, 0xFF, 0xFF, 0xFF])?;

// Read ECC originality signature
let sig = reader.read_sig()?;

// Fast NDEF read: 1 READ (TLV header) + 1 FAST_READ (payload)
let variant = version.variant().unwrap();
let ndef = reader.read_ndef_fast(variant)?;

// Standard T2T operations work too
let ndef = reader.read_ndef()?;
reader.write_ndef(&ndef_bytes)?;
```

## Frame Buffer Size

Under `no_std`, the `T2TTransceiver` trait has a const generic `N` that sets the response buffer capacity. Standard T2T operations need 20 bytes, but FAST_READ returns up to `(end - start + 1) * 4` bytes. Set `N` accordingly:

```rust
// For NTAG216 full FAST_READ (231 pages * 4 bytes = 924 bytes):
impl T2TTransceiver<924> for MyTransceiver { ... }
```

Under `alloc`, `N` is ignored and the buffer grows as needed.

## Features

| Feature | Description |
|---------|-------------|
| *(default)* | `no_std` with `heapless` fixed-capacity buffers |
| `alloc` | Use `Vec` instead of `heapless::Vec` |
| `std` | Implies `alloc` |

## License

GPL-3.0-or-later
