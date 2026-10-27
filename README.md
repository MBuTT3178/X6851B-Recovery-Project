# Infinix Note 40 Pro+ 5G (X6851B) — Android 16 (Kernel 6.12 GKI) OrangeFox Recovery

OrangeFox Recovery Project 14.1 (AOSP AP2A / SDK 35) tree and automated builds for the **Infinix Note 40 Pro+ 5G (`X6851B`)**, powered by the MediaTek Dimensity 7020 (`MT6855`) running official Android 16 (XOS 16 / Linux 6.12 GKI).

---

## Device & Architecture Specifications

| Attribute | Value |
|---|---|
| Device Model | Infinix Note 40 Pro+ 5G (`X6851B`, `Infinix-X6851B`) |
| Platform / SoC | MediaTek Dimensity 7020 (`MT6855`) |
| Target Firmware | Android 16 (Stock XOS 16) |
| Kernel Version | Linux 6.12.38 Generic Kernel Image (GKI) |
| Architecture | ARM64 (`arm64-v8a`) |
| Recovery Location | `vendor_boot` (Boot Header v4, Virtual A/B) |
| Partition Boundary | Exactly `67,108,864` bytes (64.0 MB strict hardware boundary) |
| Base Manifest | OrangeFox 14.1 (AOSP AP2A / Android 16) |
| Ramdisk Architecture | Dual ZSTD Fragments (Fragment 0: 6.12 Platform, Fragment 1: OrangeFox Recovery) |

---

## Key Hardware Features in Android 16

1. **Linux 6.12 GKI Kernel Compatibility:**
   - Preloaded with native 6.12 MediaTek MT6855 modules (`focaltech_ft3683g.ko`, `adaptive-ts.ko`, `nt37703a_fhdp_dsi_vdo_tm_tm_120hz_x6851.ko`, `spi-mt65xx.ko`).
   - Touchscreen and curved 120Hz AMOLED panel function with zero input delay or tearing.
2. **Pure AIDL KeyMint v3.0 & Gatekeeper Decryption:**
   - Upgraded to KeyMint AIDL v3.0 (`android.hardware.security.keymint@3.0-service.trustonic`) with authenticated Kinibi trustlets.
   - Decrypts FBE v2 user storage without lockups or credential drops.
3. **Dual ZSTD Adaptive Compression:**
   - Employs multi-level ZSTD compression (level 22) to seamlessly house stock 6.12 Fragment 0 (240+ kernel modules) and the full OrangeFox GUI inside the 64.0 MB hardware partition boundary.
4. **All 16 Dynamic Logical Volumes:**
   - Mapped to real logical volumes: `system`, `vendor`, `product`, `system_ext`, `odm`, `odm_dlkm`, `system_dlkm`, `vendor_dlkm`, `tr_product`, `tr_preload`, `tr_region`, `tr_carrier`, `tr_company`, `tr_misc`, `tr_manifest`, `tr_overlayfs`.
   - Data wipe, formatting, and partition backups function without unmapping hangs.

---

## Flashing Instructions

Flash the compiled `vendor_boot.img` directly to the active slot via fastboot:

```bash
# 1. Boot device into fastboot mode (Power + Volume Down)
fastboot devices

# 2. Flash to vendor_boot partition
fastboot flash vendor_boot OrangeFox-R14.1-Unofficial-X6851B-XOS16-vendor_boot.img

# 3. Reboot into OrangeFox Recovery
fastboot reboot recovery
```

---

## Local Compilation

```bash
# Sync OrangeFox 14.1
mkdir -p ~/fox_14.1 && cd ~/fox_14.1
git clone --depth=1 https://gitlab.com/OrangeFox/sync.git ~/OrangeFox_sync
~/OrangeFox_sync/orangefox_sync.sh --branch 14.1 --path ~/fox_14.1

# Clone device tree into device/infinix/X6851B
git clone https://github.com/<your-username>/X6851B-Recovery-Project.git device/infinix/X6851B

# Initialize environment & build
source build/envsetup.sh
source device/infinix/X6851B/vendorsetup.sh
lunch twrp_X6851B-ap2a-eng
mka adbd vendorbootimage -j$(nproc)

# Repack with stock Fragment 0 into 64MB boundary
python3 device/infinix/X6851B/scripts/repack_vendor_boot_a16.py \
    device/infinix/X6851B/prebuilt/stock_vendor_boot.img \
    out/target/product/X6851B/ramdisk-recovery.cpio \
    out/target/product/X6851B/vendor_boot.img
```
