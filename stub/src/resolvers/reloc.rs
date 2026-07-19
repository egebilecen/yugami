use pe_parser::section::SectionHeader;
use windows_sys::Win32::System::SystemServices::IMAGE_BASE_RELOCATION;

use debug::dprintln;

pub(crate) fn resolve_relocations(image_base_addr: usize, preferred_image_base: usize, reloc_section: &SectionHeader) -> Result<(), String> {
    dprintln!("Resolving relocations...");
    dprintln!(
        "Relocations block start RVA: 0x{:02X}",
        reloc_section.virtual_address
    );
    let mut block_offset = 0;

    loop {
        let reloc_block = unsafe {
            &*((image_base_addr + reloc_section.virtual_address as usize + block_offset)
                as *const IMAGE_BASE_RELOCATION)
        };

        if reloc_block.VirtualAddress == 0 || reloc_block.SizeOfBlock == 0 {
            break;
        }

        dprintln!("Page RVA: 0x{:02X}", reloc_block.VirtualAddress);
        dprintln!(
            "Block size: {} (0x{:02X})",
            reloc_block.SizeOfBlock,
            reloc_block.SizeOfBlock
        );

        let total_reloc_entries = (reloc_block.SizeOfBlock as usize
            - size_of::<IMAGE_BASE_RELOCATION>())
            / size_of::<u16>();
        dprintln!(
            "Entry count: {} (0x{:02X})",
            total_reloc_entries,
            total_reloc_entries
        );

        for i in 0..total_reloc_entries {
            let val = unsafe {
                *((reloc_block as *const _ as usize
                    + size_of::<IMAGE_BASE_RELOCATION>()
                    + (i * size_of::<u16>())) as *const u16)
            };

            let mask = 0b1111_0000_0000_0000;
            let reloc_type = ((val & mask) >> 12) as u8;
            let reloc_offset = val & !(mask);

            dprintln!("    [Relocation Entry {}]", i);
            dprintln!("    Relocation type: 0x{:02X} ({})", reloc_type, reloc_type);
            dprintln!(
                "    Relocation offset: 0x{:02X} ({})",
                reloc_offset,
                reloc_offset
            );

            if reloc_type != 10 {
                dprintln!("Skipping unsupported relocation type...");
                continue;
            }

            let delta = image_base_addr.wrapping_sub(preferred_image_base);
            let patch_target = (image_base_addr
                + reloc_block.VirtualAddress as usize
                + reloc_offset as usize) as *mut usize;

            unsafe {
                let curr_ptr = *patch_target;
                *patch_target = curr_ptr.wrapping_add(delta);
            }

            dprintln!("Resolved relocation.");
        }

        block_offset += reloc_block.SizeOfBlock as usize;
    }
    Ok(())
}
