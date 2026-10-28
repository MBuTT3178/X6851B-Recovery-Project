#!/usr/bin/env python3
"""
Android 16 Dual-Ramdisk Vendor Boot Repacker for Infinix Note 40 Pro+ 5G (X6851B)
Target: MediaTek Dimensity 7020 (MT6855), Linux 6.12 GKI, Boot Header v4
Includes:
- Automated CPIO permission normalization (uid=0, gid=0, mode &= ~0022) to satisfy Android 16 init security parser
- Removal of conflicting stock recovery binaries from Fragment 0
- AVB 2.0 VBMeta block insertion + AVBf footer at partition boundary (essential for MediaTek LK bootloader)
- Strict 64.0 MB (67,108,864 bytes) partition adherence
"""

import struct
import os
import sys
import io
import gzip
import lz4.block
import zstandard as zstd

def page_align(val, page_size=4096):
    return (val + page_size - 1) & ~(page_size - 1)

def normalize_cpio_security(cpio_bytes):
    """
    Android 16 init security audit:
    Any file with st_uid != 0 or writable by group/others (mode & 0022) is rejected
    with 'Skipping insecure file'. This normalizes all entries in-place.
    """
    out = io.BytesIO()
    pos = 0
    total_len = len(cpio_bytes)

    while pos < total_len:
        if pos + 110 > total_len:
            out.write(cpio_bytes[pos:])
            break

        magic = cpio_bytes[pos:pos+6]
        if magic != b'070701' and magic != b'070702':
            out.write(cpio_bytes[pos:])
            break

        header = bytearray(cpio_bytes[pos:pos+110])
        mode = int(header[14:22], 16)
        filesize = int(header[54:62], 16)
        namesize = int(header[94:102], 16)

        # Enforce uid=0 (root), gid=0 (root)
        header[22:30] = b'00000000'
        header[30:38] = b'00000000'

        # Strip group-write and others-write (mode &= ~0022)
        safe_mode = mode & ~0o022
        mode_hex = f"{safe_mode:08x}".encode('ascii')
        header[14:22] = mode_hex

        h_len = 110 + namesize
        pad_h = (4 - (h_len % 4)) % 4
        pad_f = (4 - (filesize % 4)) % 4
        entry_len = h_len + pad_h + filesize + pad_f

        out.write(header)
        out.write(cpio_bytes[pos+110:pos+entry_len])
        pos += entry_len

    return out.getvalue()

def filter_cpio_entries(cpio_bytes, remove_exact, remove_prefixes):
    """
    Filters out conflicting files from CPIO (e.g. stock recovery binaries from Fragment 0).
    """
    out = io.BytesIO()
    pos = 0
    total_len = len(cpio_bytes)
    removed_count = 0

    while pos < total_len:
        if pos + 110 > total_len:
            out.write(cpio_bytes[pos:])
            break

        magic = cpio_bytes[pos:pos+6]
        if magic not in (b'070701', b'070702'):
            out.write(cpio_bytes[pos:])
            break

        header = cpio_bytes[pos:pos+110]
        filesize = int(header[54:62], 16)
        namesize = int(header[94:102], 16)
        name = cpio_bytes[pos+110:pos+110+namesize-1].decode('utf-8', errors='ignore')

        h_len = 110 + namesize
        pad_h = (4 - (h_len % 4)) % 4
        pad_f = (4 - (filesize % 4)) % 4
        entry_len = h_len + pad_h + filesize + pad_f

        should_remove = False
        if name in remove_exact:
            should_remove = True
        else:
            for prefix in remove_prefixes:
                if name.startswith(prefix):
                    should_remove = True
                    break

        if should_remove:
            removed_count += 1
            pos += entry_len
            continue

        out.write(cpio_bytes[pos:pos+entry_len])
        pos += entry_len

    print(f"    [+] Filtered {removed_count} conflicting entries from CPIO stream.")
    return out.getvalue()

def decompress_lz4_legacy(raw_data):
    pos = 4
    blocks = []
    while pos < len(raw_data):
        if pos + 4 > len(raw_data): break
        b_size = struct.unpack_from('<I', raw_data, pos)[0]
        pos += 4
        if b_size == 0: break
        b_data = raw_data[pos:pos+b_size]
        pos += b_size
        try:
            decomp_b = lz4.block.decompress(b_data, uncompressed_size=8*1024*1024)
            blocks.append(decomp_b)
        except Exception as e:
            print(f"[!] Warning: LZ4 block decompression ended: {e}")
            break
    return b''.join(blocks)

def repack(stock_path, built_path, output_path):
    print(f"[*] Reading stock vendor_boot from: {stock_path}")
    if stock_path.endswith('.gz'):
        with gzip.open(stock_path, 'rb') as gz_f:
            stock_bytes = gz_f.read()
        stock_file = io.BytesIO(stock_bytes)
    else:
        with open(stock_path, 'rb') as f:
            stock_bytes = f.read()
        stock_file = io.BytesIO(stock_bytes)

    try:
        stock_hdr = stock_file.read(4096)
        magic, v, page_size, k_addr, r_addr, stock_r_size = struct.unpack_from('<8sIIIII', stock_hdr, 0)
        cmdline = stock_hdr[28:28+2048].split(b'\x00')[0]
        tags_addr, name, hdr_size, dtb_size, dtb_addr = struct.unpack_from('<I16sIIQ', stock_hdr, 28+2048)
        table_size, table_entry_num, table_entry_size, bootconfig_size = struct.unpack_from('<IIII', stock_hdr, 2112)

        # Offsets
        offset_ramdisk = page_size
        offset_dtb = offset_ramdisk + page_align(stock_r_size, page_size)
        offset_table = offset_dtb + page_align(dtb_size, page_size)
        offset_bootconfig = offset_table + page_align(table_size, page_size)

        # Read DTB
        stock_file.seek(offset_dtb)
        dtb_data = stock_file.read(dtb_size)
        assert dtb_data[:4] == b'\xd7\xb7\xab\x1e', f"Corrupt DTB magic: {dtb_data[:4].hex()}"

        # Read Table and find Fragment 0
        stock_file.seek(offset_table)
        table_data = stock_file.read(table_size)
        frag0_size, frag0_offset, frag0_type = struct.unpack_from('<III', table_data, 0)

        # Read Fragment 0
        stock_file.seek(offset_ramdisk + frag0_offset)
        raw_frag0_data = stock_file.read(frag0_size)

        # Read bootconfig
        stock_file.seek(offset_bootconfig)
        raw_bc = stock_file.read(bootconfig_size)
        bc_str = raw_bc.decode('utf-8', errors='ignore')
        if "androidboot.selinux=permissive" not in bc_str:
            bc_str = "androidboot.selinux=permissive\n" + bc_str.strip() + "\n"
        bootconfig_data = bc_str.encode('utf-8')

        # Read stock AVB0 (VBMeta struct)
        avb_idx = stock_bytes.find(b'AVB0')
        if avb_idx != -1:
            vbmeta_data = stock_bytes[avb_idx:avb_idx+640]
            print(f"[+] Found stock AVB0 VBMeta block at offset {avb_idx} ({len(vbmeta_data)} bytes)")
        else:
            vbmeta_data = b''
            print("[!] Warning: No AVB0 block found in stock image!")

    finally:
        stock_file.close()

    print(f"[+] Stock parameters: Header v{v}, DTB size: {dtb_size}, Frag0 size: {frag0_size}")

    # Decompress Fragment 0 (Stock A16 platform CPIO)
    if raw_frag0_data[:4] == b'\x02\x21\x4c\x18':
        uncompressed_frag0 = decompress_lz4_legacy(raw_frag0_data)
    elif raw_frag0_data[:4] == b'\x28\xb5\x2f\xfd':
        dctx = zstd.ZstdDecompressor()
        uncompressed_frag0 = dctx.decompress(raw_frag0_data)
    elif raw_frag0_data[:6] == b'070701' or raw_frag0_data[:6] == b'070702':
        uncompressed_frag0 = raw_frag0_data
    else:
        raise ValueError(f"Unknown Fragment 0 compression: {raw_frag0_data[:4].hex()}")

    print(f"[+] Frag0 uncompressed size: {len(uncompressed_frag0)} bytes")

    # Filter out stock recovery binaries from Fragment 0 so Fragment 1 (OrangeFox) has exclusive control
    print("[+] Filtering out stock recovery binaries from Fragment 0...")
    remove_exact = {
        'system/bin/recovery',
        'system/lib64/librecovery_ui.so',
        'system/lib64/librecovery_ui_ext.so',
        'system/etc/init/android.hardware.boot-service.mtk_recovery.rc',
        'system/etc/init/android.hardware.health-service.example_recovery.rc',
        'system/etc/init/servicemanager.recovery.rc'
    }
    uncompressed_frag0 = filter_cpio_entries(uncompressed_frag0, remove_exact, [])

    # Sanitize Fragment 0 VINTF paths & version
    p1 = b'system/etc/vintf/manifest/android.hardware.boot-service.mtk.xml'
    t1 = b'vendor/etc/vintf/manifest/android.hardware.boot-service.mtk.xml'
    p2 = b'system/etc/vintf/manifest/android.hardware.health-service.example.xml'
    t2 = b'vendor/etc/vintf/manifest/android.hardware.health-service.example.xml'
    uncompressed_frag0 = uncompressed_frag0.replace(p1, t1).replace(p2, t2)
    uncompressed_frag0 = uncompressed_frag0.replace(b'version="9.0"', b'version="8.0"')

    # Patch mcDrvModule.ko in Frag0 if present (v10 -> v9 API)
    patches = [
        (b'\x40\x01\x80\x52', b'\x20\x01\x80\x52'),
        (b'\x4d\x01\x80\x52', b'\x2d\x01\x80\x52'),
        (b'\x48\x01\x80\x52', b'\x28\x01\x80\x52'),
        (b'\x43\x01\x80\x52', b'\x23\x01\x80\x52'),
    ]
    name_idx = uncompressed_frag0.find(b'mcDrvModule.ko')
    if name_idx != -1:
        elf_idx = uncompressed_frag0.find(b'\x7fELF', name_idx)
        if elf_idx != -1:
            ko_len = 338192
            ko_data = uncompressed_frag0[elf_idx:elf_idx+ko_len]
            for old_bytes, new_bytes in patches:
                if old_bytes in ko_data:
                    ko_data = ko_data.replace(old_bytes, new_bytes)
            uncompressed_frag0 = uncompressed_frag0[:elf_idx] + ko_data + uncompressed_frag0[elf_idx+ko_len:]

    # Normalize Frag0 CPIO ownership and permissions
    print("[+] Normalizing Fragment 0 CPIO permissions (uid=0, gid=0, go-w)...")
    uncompressed_frag0 = normalize_cpio_security(uncompressed_frag0)

    # Read built recovery ramdisk
    print(f"[*] Reading built recovery artifact from: {built_path}")
    with open(built_path, 'rb') as bf:
        built_hdr = bf.read(4096)
        if built_hdr[:8] == b'VNDRBOOT':
            # It is a vendor_boot.img: extract Fragment 1 from table
            b_table_size, b_table_entry_num, b_table_entry_size = struct.unpack_from('<III', built_hdr, 2112)
            b_r_size = struct.unpack_from('<I', built_hdr, 24)[0]
            b_dtb_size = struct.unpack_from('<I', built_hdr, 2100)[0]
            b_offset_table = page_size + page_align(b_r_size, page_size) + page_align(b_dtb_size, page_size)
            bf.seek(b_offset_table)
            b_table = bf.read(b_table_size)
            if b_table_entry_num >= 2:
                rec_entry = b_table[b_table_entry_size : 2 * b_table_entry_size]
            else:
                rec_entry = b_table[:b_table_entry_size]
            rec_size, rec_offset, rec_type = struct.unpack_from('<III', rec_entry, 0)
            bf.seek(page_size + rec_offset)
            raw_rec = bf.read(rec_size)
        else:
            # It is a raw CPIO or compressed ramdisk
            bf.seek(0)
            raw_rec = bf.read()

    # Decompress recovery ramdisk if compressed
    if raw_rec[:4] == b'\x28\xb5\x2f\xfd':
        dctx = zstd.ZstdDecompressor()
        uncompressed_rec = dctx.decompress(raw_rec)
    elif raw_rec[:2] == b'\x1f\x8b':
        uncompressed_rec = gzip.decompress(raw_rec)
    elif raw_rec[:4] == b'\x02\x21\x4c\x18':
        uncompressed_rec = decompress_lz4_legacy(raw_rec)
    else:
        uncompressed_rec = raw_rec

    print(f"[+] Frag1 uncompressed size: {len(uncompressed_rec)} bytes")

    # Sanitize Frag1 VINTF
    uncompressed_rec = uncompressed_rec.replace(p1, t1).replace(p2, t2)
    uncompressed_rec = uncompressed_rec.replace(b'version="9.0"', b'version="8.0"')

    # Normalize Frag1 CPIO ownership and permissions (CRITICAL FIX FOR INSECURE FILE ERROR)
    print("[+] Normalizing Fragment 1 CPIO permissions (uid=0, gid=0, go-w)...")
    uncompressed_rec = normalize_cpio_security(uncompressed_rec)

    # Multi-level adaptive ZSTD compression
    target_part_size = 67108864 # 64.0 MB strict partition limit
    final_padded = None
    final_data_len = 0

    cmdline_str = cmdline.decode('utf-8', errors='ignore')
    if "bootconfig" not in cmdline_str:
        cmdline_str = (cmdline_str + " bootconfig").strip()
    cmdline_bytes = cmdline_str.encode('utf-8')[:2047]

    for zstd_level in [22, 21, 19]:
        cctx = zstd.ZstdCompressor(level=zstd_level)
        frag0_zstd = cctx.compress(uncompressed_frag0)
        frag1_zstd = cctx.compress(uncompressed_rec)
        print(f"    [*] ZSTD Level {zstd_level}: Frag0={len(frag0_zstd)/1024/1024:.2f} MB, Frag1={len(frag1_zstd)/1024/1024:.2f} MB")

        total_ramdisk = frag0_zstd + frag1_zstd
        vendor_ramdisk_size = len(total_ramdisk)

        # Construct Ramdisk Table
        entry0 = bytearray(108)
        struct.pack_into('<III', entry0, 0, len(frag0_zstd), 0, 1) # type 1 = PLATFORM
        entry1 = bytearray(108)
        struct.pack_into('<III', entry1, 0, len(frag1_zstd), len(frag0_zstd), 2) # type 2 = RECOVERY
        rec_name_bytes = b'recovery' + b'\x00' * (32 - len(b'recovery'))
        entry1[12:12+32] = rec_name_bytes
        new_table_data = bytes(entry0 + entry1)
        new_table_size = len(new_table_data)

        hdr = bytearray(stock_hdr)
        struct.pack_into('<I', hdr, 24, vendor_ramdisk_size)
        hdr[28:28+2048] = b'\x00' * 2048
        hdr[28:28+len(cmdline_bytes)] = cmdline_bytes
        struct.pack_into('<IIII', hdr, 2112, new_table_size, 2, 108, len(bootconfig_data))

        out_parts = []
        out_parts.append(bytes(hdr))
        out_parts.append(total_ramdisk)
        pad1 = page_align(len(total_ramdisk), page_size) - len(total_ramdisk)
        if pad1 > 0: out_parts.append(b'\x00' * pad1)

        out_parts.append(dtb_data)
        pad2 = page_align(len(dtb_data), page_size) - len(dtb_data)
        if pad2 > 0: out_parts.append(b'\x00' * pad2)

        out_parts.append(new_table_data)
        pad3 = page_align(len(new_table_data), page_size) - len(new_table_data)
        if pad3 > 0: out_parts.append(b'\x00' * pad3)

        out_parts.append(bootconfig_data)
        pad4 = page_align(len(bootconfig_data), page_size) - len(bootconfig_data)
        if pad4 > 0: out_parts.append(b'\x00' * pad4)

        # Append AVB0 VBMeta block if present in stock
        if len(vbmeta_data) > 0:
            vbm_offset = (
                page_size +
                page_align(len(total_ramdisk), page_size) +
                page_align(len(dtb_data), page_size) +
                page_align(len(new_table_data), page_size) +
                page_align(len(bootconfig_data), page_size)
            )
            out_parts.append(vbmeta_data)
            pad5 = page_align(len(vbmeta_data), page_size) - len(vbmeta_data)
            if pad5 > 0: out_parts.append(b'\x00' * pad5)
        else:
            vbm_offset = 0

        final_data = b''.join(out_parts)
        final_data_len = len(final_data)

        # 64 bytes reserved at the partition end for AvbFooter (AVBf)
        required_len = final_data_len + 64
        if required_len <= target_part_size:
            headroom = target_part_size - 64 - final_data_len
            if len(vbmeta_data) > 0:
                footer = struct.pack(
                    '>4sIIQQQ28s',
                    b'AVBf',
                    1,
                    0,
                    vbm_offset,
                    vbm_offset,
                    len(vbmeta_data),
                    b'\x00' * 28
                )
            else:
                footer = b'\x00' * 64

            final_padded = final_data + (b'\x00' * headroom) + footer
            print(f"    [+] Successfully fits at ZSTD level {zstd_level}: {final_data_len} bytes + {len(footer)}B footer <= {target_part_size} bytes (Headroom: {headroom/1024:.2f} KB)")
            break

    if final_padded is None:
        raise ValueError(f"Image size {final_data_len} exceeds partition boundary {target_part_size} bytes!")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'wb') as out_f:
        out_f.write(final_padded)

    print(f"[+] Output written to: {output_path}")
    print(f"[+] Final file size: {len(final_padded)} bytes (Exactly 64.0 MB)")
    print("[+] Android 16 Dual-Ramdisk Assembly Complete with AVBf Footer!")

if __name__ == '__main__':
    if len(sys.argv) >= 4:
        repack(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print("Usage: repack_vendor_boot_a16.py <stock_vendor_boot> <built_ramdisk_or_image> <output_image>")
        sys.exit(1)
