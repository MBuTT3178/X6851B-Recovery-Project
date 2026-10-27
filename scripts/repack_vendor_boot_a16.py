import os, sys, struct, io, lz4.block, hashlib

def page_align(val, page_size=4096):
    return (val + page_size - 1) & ~(page_size - 1)

def compress_lz4_legacy(data):
    # LZ4 legacy format:
    # 4 bytes magic: 0x184C2102
    # Then blocks: 4 bytes little-endian compressed block size, followed by compressed block data
    out = io.BytesIO()
    out.write(struct.pack('<I', 0x184C2102))
    block_size = 8 * 1024 * 1024
    pos = 0
    while pos < len(data):
        chunk = data[pos:pos+block_size]
        pos += len(chunk)
        comp_chunk = lz4.block.compress(chunk, mode='high_compression', store_size=False)
        out.write(struct.pack('<I', len(comp_chunk)))
        out.write(comp_chunk)
    return out.getvalue()

def build_reco():
    print("=== ASSEMBLING CLEAN LZ4 LEGACY RECOVERY FOR X6851B (ANDROID 16) ===")

    stock_vendor_boot = "/mnt/c/Users/amv31/Downloads/extracted_x16/vendor_boot.img"
    x15_img = "/mnt/c/Users/amv31/Downloads/OrangeFox-X6851B-XOS15.img"
    rec_cpio_path = "/mnt/c/Users/amv31/Downloads/extracted_x16/test_ofox_rec.cpio"
    output_path = "/mnt/c/Users/amv31/Downloads/OrangeFox-R14.1-Unofficial-X6851B-XOS16-LZ4-vendor_boot.img"

    # 1. Read stock header v4 from stock Android 16 vendor_boot
    with open(stock_vendor_boot, "rb") as f:
        stock_hdr = bytearray(f.read(4096))
        # Read stock DTB
        f.seek(0x01FC0000)
        dtb_data = f.read(216341)
        # Read stock bootconfig
        f.seek(0x01FF6000)
        bootconfig_data = f.read(94)

    page_size = 4096
    target_part_size = 67108864 # 64.0 MB

    # 2. Extract clean Frag 0 from Rama's working recovery (first_stage_ramdisk CPIO)
    with open(x15_img, "rb") as f:
        f.seek(4096)
        raw_f0_lz4 = f.read(2689186)

    # Decompress Rama's Frag 0
    pos = 4
    blocks = []
    while pos < len(raw_f0_lz4):
        b_size = struct.unpack_from('<I', raw_f0_lz4, pos)[0]
        pos += 4
        if b_size == 0: break
        b_data = raw_f0_lz4[pos:pos+b_size]
        pos += b_size
        decomp = lz4.block.decompress(b_data, uncompressed_size=8*1024*1024)
        blocks.append(decomp)
    uncomp_f0 = b''.join(blocks)
    print(f"Frag 0 uncompressed size: {len(uncomp_f0):,} bytes")

    # Recompress Frag 0 with LZ4 legacy
    frag0_lz4 = compress_lz4_legacy(uncomp_f0)
    print(f"Frag 0 LZ4 Legacy size: {len(frag0_lz4):,} bytes ({len(frag0_lz4)/1024/1024:.2f} MB)")

    # 3. Read our Android 16 recovery CPIO (with Linux 6.12 modules & AIDL Trustonic KeyMint)
    with open(rec_cpio_path, "rb") as f:
        uncomp_rec = f.read()
    print(f"Frag 1 (Recovery) uncompressed size: {len(uncomp_rec):,} bytes ({len(uncomp_rec)/1024/1024:.2f} MB)")

    # Compress Frag 1 with LZ4 legacy
    frag1_lz4 = compress_lz4_legacy(uncomp_rec)
    print(f"Frag 1 (Recovery) LZ4 Legacy size: {len(frag1_lz4):,} bytes ({len(frag1_lz4)/1024/1024:.2f} MB)")

    total_ramdisk = frag0_lz4 + frag1_lz4
    vendor_ramdisk_size = len(total_ramdisk)
    print(f"\nTotal vendor ramdisk size: {vendor_ramdisk_size:,} bytes ({vendor_ramdisk_size/1024/1024:.2f} MB)")

    # 4. Construct Table entries
    # Entry 0: PLATFORM (Frag 0)
    entry0 = bytearray(108)
    struct.pack_into('<III', entry0, 0, len(frag0_lz4), 0, 1) # size, offset=0, type=1
    # Entry 1: RECOVERY (Frag 1)
    entry1 = bytearray(108)
    struct.pack_into('<III', entry1, 0, len(frag1_lz4), len(frag0_lz4), 2) # size, offset=len(frag0), type=2
    rec_name = b'recovery' + b'\x00' * (32 - len(b'recovery'))
    entry1[12:12+32] = rec_name
    table_data = bytes(entry0 + entry1)
    table_size = len(table_data)

    # 5. Build Header v4
    cmdline = b"bootopt=64S3,32N2,64N2 bootconfig"
    struct.pack_into('<I', stock_hdr, 24, vendor_ramdisk_size)
    stock_hdr[28:28+2048] = b'\x00' * 2048
    stock_hdr[28:28+len(cmdline)] = cmdline
    # Update table size, entry count, entry size, bootconfig size
    struct.pack_into('<IIII', stock_hdr, 2112, table_size, 2, 108, len(bootconfig_data))

    # 6. Assemble partitions with 4096-byte page alignment
    parts = []
    parts.append(bytes(stock_hdr)) # page 0

    parts.append(total_ramdisk)
    pad_rd = page_align(len(total_ramdisk), page_size) - len(total_ramdisk)
    if pad_rd > 0: parts.append(b'\x00' * pad_rd)

    parts.append(dtb_data)
    pad_dtb = page_align(len(dtb_data), page_size) - len(dtb_data)
    if pad_dtb > 0: parts.append(b'\x00' * pad_dtb)

    parts.append(table_data)
    pad_tbl = page_align(len(table_data), page_size) - len(table_data)
    if pad_tbl > 0: parts.append(b'\x00' * pad_tbl)

    parts.append(bootconfig_data)
    pad_bc = page_align(len(bootconfig_data), page_size) - len(bootconfig_data)
    if pad_bc > 0: parts.append(b'\x00' * pad_bc)

    final_img = b''.join(parts)
    print(f"\nFinal unpadded size: {len(final_img):,} bytes ({len(final_img)/1024/1024:.2f} MB)")

    if len(final_img) > target_part_size:
        raise ValueError(f"Image exceeds partition size! {len(final_img)} > {target_part_size}")

    headroom = target_part_size - len(final_img)
    print(f"Headroom to 64MB partition boundary: {headroom:,} bytes ({headroom/1024/1024:.2f} MB)")
    final_padded = final_img + b'\x00' * headroom

    with open(output_path, "wb") as f:
        f.write(final_padded)

    print(f"[+] Output written to: {output_path}")
    print(f"[+] Exact size: {len(final_padded):,} bytes (64.0 MB strict hardware boundary)")
    sha = hashlib.sha256(final_padded).hexdigest()
    print(f"[+] SHA-256: {sha}")
    print("=== RECOVERY ASSEMBLY SUCCESSFUL ===")

if __name__ == '__main__':
    build_reco()
