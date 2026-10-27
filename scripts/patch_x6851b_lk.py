#!/usr/bin/env python3
"""
Renkai / Fenrir Bootloader Patcher for Infinix Note 40 Pro+ 5G (X6851B) Android 16
Applies:
  1. Force Green State (bypasses Orange State 5s warning, sets androidboot.verifiedbootstate=green)
  2. Sec Vfy Policy Override (disables signature checks across lk, bl2_ext, aee)
  3. Spoof Lock State (forces LKS_LOCK = 4 across lk, bl2_ext, aee to pass Play Integrity Strong/Device)
  4. Spoof SBoot State (ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP across lk, bl2_ext, aee)
  5. Prevent Seccfg Relock (across lk, aee)
  6. Multi-partition GFH hash override re-signing via liblk
"""

import sys, os, hashlib
from liblk.image import LkImage
from liblk.structures.certificate import Certificate

STOCK_PATH = '/mnt/c/Users/amv31/Downloads/extracted_x16/lk_stock_x6851b.img'
PATCHED_PATH = '/mnt/c/Users/amv31/Downloads/extracted_x16/lk_patched_x6851b.img'

print(f'Loading stock X6851B LK: {STOCK_PATH}')
img = LkImage(STOCK_PATH)

# Trailing bytes (padding / certs)
region_end = 0
for partition in img.partitions.values():
    region_end = max(region_end, partition.end_offset)
    for cert in partition.certs:
        region_end = max(region_end, cert.end_offset)
trailing = bytes(img.contents[region_end:])

print(f'Detected trailing data: {len(trailing)} bytes')

applied_patches = []

def patch_partition_bytes(part_name, target_pattern, replacement, description, max_matches=None):
    if part_name not in img.partitions:
        print(f'[-] Partition {part_name} not found!')
        return 0
    part = img.partitions[part_name]
    data = bytearray(part.data)
    count = 0
    idx = 0
    while True:
        pos = data.find(target_pattern, idx)
        if pos == -1:
            break
        data[pos:pos+len(replacement)] = replacement
        count += 1
        applied_patches.append((part_name, description, hex(pos)))
        idx = pos + len(replacement)
        if max_matches and count >= max_matches:
            break
    part.data = bytes(data)
    print(f'[+] {part_name}: {description} -> {count} match(es)')
    return count

# 1. Force Green State in lk
# get_boot_state(): 0x5F03C
# Stock: c8 03 00 d0 00 a1 4f b9 c0 03 5f d6 (adrp x8, #0xd9000; ldr w0, [x8, #0xfa0]; ret)
# Replacement: mov w0, #0; ret; nop
patch_partition_bytes(
    'lk',
    bytes.fromhex('c80300d000a14fb9c0035fd6'),
    bytes.fromhex('00008052c0035fd61f2003d5'),
    'Force get_boot_state to return 0 (GREEN)',
    max_matches=1
)

# set_boot_state(w0): 0x5F048
# Stock: c8 03 00 d0 00 a1 0f b9 c0 03 5f d6 (adrp x8, #0xd9000; str w0, [x8, #0xfa0]; ret)
# Replacement: adrp x8, #0xd9000; str wzr, [x8, #0xfa0]; ret
patch_partition_bytes(
    'lk',
    bytes.fromhex('c80300d000a10fb9c0035fd6'),
    bytes.fromhex('c80300d01fa10fb9c0035fd6'),
    'Force set_boot_state to store 0 (GREEN)',
    max_matches=1
)

# 2. Sec Vfy Policy Override
# Stock: 00 01 00 b4 fd 7b bf a9 (cbz x0, ...; stp x29, x30, ...)
# Replacement: 00 00 80 52 c0 03 5f d6 (mov w0, #0; ret)
for part in ['lk', 'bl2_ext', 'aee']:
    patch_partition_bytes(
        part,
        bytes.fromhex('000100b4fd7bbfa9'),
        bytes.fromhex('00008052c0035fd6'),
        'sec_get_vfy_policy return 0 (bypass verification)',
        max_matches=1
    )

# 3. Spoof Lock State
# Stock: 20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91
# Replacement: 88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 (mov w8, #4; str w8, [x0]; mov w0, #0; ret)
for part in ['lk', 'bl2_ext', 'aee']:
    patch_partition_bytes(
        part,
        bytes.fromhex('200200b4fd7bbea9f30b00f9fd030091'),
        bytes.fromhex('88008052080000b900008052c0035fd6'),
        'spoof_lock_state to LKS_LOCK (4)',
        max_matches=1
    )

# 4. Spoof SBoot State
# Stock: fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52
# Replacement: 48 04 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5
for part in ['lk', 'bl2_ext', 'aee']:
    patch_partition_bytes(
        part,
        bytes.fromhex('fd7bbea9f30b00f9fd030091f30300aa20008052'),
        bytes.fromhex('48048052080000b900008052c0035fd61f2003d5'),
        'spoof_sboot_state to ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP'
    )

# 5. Prevent Seccfg Relock
# Stock: fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 2a 28 00 80 52
# Replacement: 00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5
for part in ['lk', 'aee']:
    patch_partition_bytes(
        part,
        bytes.fromhex('fd7bbea9f30b00f9fd030091f303002a28008052'),
        bytes.fromhex('00008052c0035fd61f2003d51f2003d51f2003d5'),
        'prevent_seccfg_relock'
    )

print('\n=== Re-signing modified partitions (Certificate Bypass OVERRIDE) ===')
re_signed = []
for name, partition in img.partitions.items():
    if partition.cert2 is None:
        continue
    status = partition.matches_cert2()
    if status:
        print(f'  [-] Partition {name}: matches original cert2, skipping re-sign')
        continue
    print(f'  [*] Partition {name}: modified, injecting hash override block...')
    header_hash, image_hash = partition.compute_hashes()
    original_cert = bytes(partition.cert2.data)
    cert_obj = Certificate.from_bytes(original_cert)
    override_block = cert_obj.build_hash_override_block(header_hash, image_hash)
    partition.cert2.data = override_block + original_cert
    re_signed.append(name)
    print(f'  [+] Partition {name}: successfully re-signed!')

img._rebuild_contents()
img.contents = bytearray(img.contents) + bytearray(trailing)

with open(PATCHED_PATH, 'wb') as f:
    f.write(bytes(img.contents))

print(f'\nPatched image written to: {PATCHED_PATH}')
print(f'Output Size: {len(img.contents):,} bytes')
sha = hashlib.sha256(bytes(img.contents)).hexdigest()
print(f'Output SHA256: {sha}')

# Verification
print('\n=== Verifying generated image with LkImage ===')
v_img = LkImage(PATCHED_PATH)
for name, partition in v_img.partitions.items():
    print(f'  - {name}: size={len(partition.data):,}, cert2_status={partition.matches_cert2()}')

print('\nTotal applied patches:')
for part, desc, pos in applied_patches:
    print(f'  - [{part}] {desc} at {pos}')

print('\nSUCCESS!')
