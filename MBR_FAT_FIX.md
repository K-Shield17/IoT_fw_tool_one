# MBR/FAT extraction fix

This revision restores the Binwalk 3.1.0 extraction chain required for disk-style firmware images.

## Restored unchanged upstream files

- `tools/binwalk-lite/src/signatures/mbr.rs`
- `tools/binwalk-lite/src/signatures/fat.rs`
- `tools/binwalk-lite/src/structures/mbr.rs`
- `tools/binwalk-lite/src/structures/fat.rs`
- `tools/binwalk-lite/src/extractors/mbr.rs`

The already-retained `tools/binwalk-lite/src/extractors/tsk.rs` is used for FAT recovery.

## Registry changes

- `signatures.rs`: registers `mbr` and `fat`
- `structures.rs`: registers `mbr` and `fat`
- `extractors.rs`: registers `mbr`
- `magic.rs`: restores the upstream MBR and FAT signature blocks

## Expected recursive path

`firmware.img -> MBR -> FAT32_partition.0 -> FAT filesystem -> rootfs/ -> bootcode.bin, kernel.img, start.elf, config.txt, DTBs, ...`

The existing SquashFS path remains unchanged.
