//! Wrappers used by `dev-tools/ct-disasm/check.sh` to verify that the
//! constant-time hot paths in `base16ct`, `base32ct`, and `base64ct` compile
//! to branch-free machine code.
//!
//! Each wrapper:
//!   * is `#[unsafe(no_mangle)]` so the disassembly script can find it by name,
//!   * is `#[inline(never)]` so it shows up as its own symbol,
//!   * calls a public crate API on a fixed-length buffer with `black_box`-ed
//!     inputs/outputs so the inner `#[inline(always)]` CT helpers
//!     (`decode_nibble`, `decode_5bits`, `decode_6bits`, `is_pad_ct`, etc.)
//!     get inlined into our wrapper, where the checker can scan them.
//!
//! The wrappers deliberately use compile-time-known buffer lengths so that
//! length-dependent branches in the public API collapse to constants and the
//! only branches that *can* remain are byte-value-dependent — which is what
//! we want to flag.
//!
//! This crate is `no_std`-compatible to keep the disassembly tight; it never
//! allocates.

#![no_std]
#![allow(missing_docs)] // public ABI of these wrappers is intentionally minimal

use core::hint::black_box;

use base16ct::{lower as hex_lower, mixed as hex_mixed, upper as hex_upper};
use base32ct::{Base32, Base32Upper, Encoding as Base32Encoding};
use base64ct::{Base64, Base64Unpadded, Encoding as Base64Encoding};

// ---- base16ct -------------------------------------------------------------

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn ct_disasm_base16_lower_decode(input: &[u8; 64], output: &mut [u8; 32]) -> i32 {
    let input = black_box(input);
    let output = black_box(output);
    match hex_lower::decode(input, output) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn ct_disasm_base16_lower_encode(input: &[u8; 32], output: &mut [u8; 64]) -> i32 {
    let input = black_box(input);
    let output = black_box(output);
    match hex_lower::encode(input, output) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn ct_disasm_base16_upper_decode(input: &[u8; 64], output: &mut [u8; 32]) -> i32 {
    let input = black_box(input);
    let output = black_box(output);
    match hex_upper::decode(input, output) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn ct_disasm_base16_upper_encode(input: &[u8; 32], output: &mut [u8; 64]) -> i32 {
    let input = black_box(input);
    let output = black_box(output);
    match hex_upper::encode(input, output) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn ct_disasm_base16_mixed_decode(input: &[u8; 64], output: &mut [u8; 32]) -> i32 {
    let input = black_box(input);
    let output = black_box(output);
    match hex_mixed::decode(input, output) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

// ---- base32ct -------------------------------------------------------------

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn ct_disasm_base32_lower_decode(input: &[u8; 56], output: &mut [u8; 35]) -> i32 {
    let input = black_box(input);
    let output = black_box(output);
    match Base32::decode(input, output) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn ct_disasm_base32_lower_encode(input: &[u8; 35], output: &mut [u8; 56]) -> i32 {
    let input = black_box(input);
    let output = black_box(output);
    match Base32::encode(input, output) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn ct_disasm_base32_upper_decode(input: &[u8; 56], output: &mut [u8; 35]) -> i32 {
    let input = black_box(input);
    let output = black_box(output);
    match Base32Upper::decode(input, output) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

// ---- base64ct -------------------------------------------------------------

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn ct_disasm_base64_padded_decode(input: &[u8; 64], output: &mut [u8; 48]) -> i32 {
    let input = black_box(input);
    let output = black_box(output);
    match Base64::decode(input, output) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn ct_disasm_base64_padded_encode(input: &[u8; 48], output: &mut [u8; 64]) -> i32 {
    let input = black_box(input);
    let output = black_box(output);
    match Base64::encode(input, output) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn ct_disasm_base64_unpadded_decode(input: &[u8; 64], output: &mut [u8; 48]) -> i32 {
    let input = black_box(input);
    let output = black_box(output);
    match Base64Unpadded::decode(input, output) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
