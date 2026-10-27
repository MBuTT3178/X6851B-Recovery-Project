#!/usr/bin/env python3
import struct
import os
import io
import zstandard as zstd
import lz4.block

def page_align(val, page_size=4096):
    return (val + page_size - 1) & ~(page_size - 1)

def repack(stock_path, built_path, output_path):
    print(f"Reading stock vendor_boot: {stock_path}")
    with open(stock_path, 'rb') as stock_file:
        stock_hdr = stock_file.read(4096)
        magic, v, page_size, k_addr, r_addr, stock_r_size = struct.unpack_from('<8sIIIII', stock_hdr, 0)
        cmdline = stock_hdr[28:28+2048].split(b'\x00')[0]
        tags_addr, name, hdr_size, dtb_size, dtb_addr = struct.unpack_from('<I16sIIQ', stock_hdr, 28+2048)
        table_size, table_entry_num, table_entry_size, bootconfig_size = struct.unpack_from('<IIII', stock_hdr, 2112)
        
        offset_ramdisk = page_size
        offset_dtb = offset_ramdisk + page_align(stock_r_size, page_size)
        offset_table = offset_dtb + page_align(dtb_size, page_size)
        offset_bootconfig = offset_table + page_align(table_size, page_size)
        
        stock_file.seek(offset_dtb)
        dtb_data = stock_file.read(dtb_size)
        
        stock_file.seek(offset_table)
        table_data = stock_file.read(table_size)
        frag0_size, frag0_offset, frag0_type = struct.unpack_from('<III', table_data, 0)
        
        stock_file.seek(offset_ramdisk + frag0_offset)
        raw_frag0_data = stock_file.read(frag0_size)
        
        stock_file.seek(offset_bootconfig)
        raw_bc = stock_file.read(bootconfig_size)
        bc_str = raw_bc.decode('utf-8', errors='ignore')
        if "androidboot.selinux=permissive" not in bc_str:
            bc_str = "androidboot.selinux=permissive\n" + bc_str.strip() + "\n"
        bootconfig_data = bc_str.encode('utf-8')

    print(f"Stock header: version={v}, dtb_size={dtb_size}, bootconfig_size={bootconfig_size}")
    print(f"Stock Fragment 0 size: {frag0_size} bytes")

    pos = 4
    blocks = []
    while pos < len(raw_frag0_data):
        if pos + 4 > len(raw_frag0_data): break
        b_size = struct.unpack_from('<I', raw_frag0_data, pos)[0]
        pos += 4
        if b_size == 0: break
        b_data = raw_frag0_data[pos:pos+b_size]
        pos += b_size
        try:
            decomp_b = lz4.block.decompress(b_data, uncompressed_size=8*1024*1024)
            blocks.append(decomp_b)
        except Exception as e:
            print("Fragment 0 decompress block error:", e)
            break
    uncompressed_frag0 = b''.join(blocks)
    print(f"Fragment 0 uncompressed size: {len(uncompressed_frag0)} bytes")

    p1 = b'system/etc/vintf/manifest/android.hardware.boot-service.mtk.xml'
    t1 = b'vendor/etc/vintf/manifest/android.hardware.boot-service.mtk.xml'
    p2 = b'system/etc/vintf/manifest/android.hardware.health-service.example.xml'
    t2 = b'vendor/etc/vintf/manifest/android.hardware.health-service.example.xml'

    if p1 in uncompressed_frag0 or p2 in uncompressed_frag0:
        uncompressed_frag0 = uncompressed_frag0.replace(p1, t1).replace(p2, t2)
    if b'version="9.0"' in uncompressed_frag0:
        uncompressed_frag0 = uncompressed_frag0.replace(b'version="9.0"', b'version="8.0"')

    name_idx = uncompressed_frag0.find(b'mcDrvModule.ko')
    if name_idx != -1:
        elf_idx = uncompressed_frag0.find(b'\x7fELF', name_idx)
        if elf_idx != -1:
            ko_len = 338192
            ko_data = uncompressed_frag0[elf_idx:elf_idx+ko_len]
            patches = [
                (b'\x40\x01\x80\x52', b'\x20\x01\x80\x52'),
                (b'\x4d\x01\x80\x52', b'\x2d\x01\x80\x52'),
                (b'\x48\x01\x80\x52', b'\x28\x01\x80\x52'),
                (b'\x43\x01\x80\x52', b'\x23\x01\x80\x52'),
            ]
            for old_bytes, new_bytes in patches:
                count = ko_data.count(old_bytes)
                if count > 0:
                    ko_data = ko_data.replace(old_bytes, new_bytes)
            uncompressed_frag0 = uncompressed_frag0[:elf_idx] + ko_data + uncompressed_frag0[elf_idx+ko_len:]

    print(f"Reading built recovery ramdisk: {built_path}")
    with open(built_path, 'rb') as built_file:
        raw_rec_data = built_file.read()

    uncompressed_rec = raw_rec_data
    if p1 in uncompressed_rec or p2 in uncompressed_rec:
        uncompressed_rec = uncompressed_rec.replace(p1, t1).replace(p2, t2)
    if b'version="9.0"' in uncompressed_rec:
        uncompressed_rec = uncompressed_rec.replace(b'version="9.0"', b'version="8.0"')

    cmdline_str = cmdline.decode('utf-8', errors='ignore')
    if "bootconfig" not in cmdline_str:
        cmdline_str = (cmdline_str + " bootconfig").strip()
    cmdline_bytes = cmdline_str.encode('utf-8')[:2047]

    target_part_size = 67108864
    final_padded = None
    final_data_len = 0

    for zstd_level in [22, 21, 19]:
        cctx = zstd.ZstdCompressor(level=zstd_level)
        frag0_zstd = cctx.compress(uncompressed_frag0)
        frag1_zstd = cctx.compress(uncompressed_rec)
        print(f"ZSTD Level {zstd_level}: Frag0={len(frag0_zstd)} bytes, Frag1={len(frag1_zstd)} bytes")

        total_ramdisk = frag0_zstd + frag1_zstd
        vendor_ramdisk_size = len(total_ramdisk)

        entry0 = bytearray(108)
        struct.pack_into('<III', entry0, 0, len(frag0_zstd), 0, 1)
        entry1 = bytearray(108)
        struct.pack_into('<III', entry1, 0, len(frag1_zstd), len(frag0_zstd), 2)
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

        final_data = b''.join(out_parts)
        final_data_len = len(final_data)

        if final_data_len <= target_part_size:
            headroom = target_part_size - final_data_len
            print(f"Fit achieved at level {zstd_level}: {final_data_len} <= {target_part_size} ({headroom} bytes headroom)")
            final_padded = final_data + b'\x00' * headroom
            break

    if final_padded is None:
        raise ValueError(f"Image exceeds partition boundary: {final_data_len} > {target_part_size}")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'wb') as out_f:
        out_f.write(final_padded)

    print(f"Successfully generated: {output_path}")

if __name__ == '__main__':
    import sys
    if len(sys.argv) >= 4:
        repack(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print("Usage: python repack_vendor_boot_a16.py <stock_vendor_boot.img> <built_recovery_ramdisk.cpio> <output_vendor_boot.img>")
