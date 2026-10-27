#
# Copyright (C) 2024-2026 The LineageOS Project
#
# SPDX-License-Identifier: Apache-2.0
#

# Inherit from X6851B device
$(call inherit-product, device/infinix/X6851B/device.mk)

# Inherit common TWRP config
$(call inherit-product, vendor/twrp/config/common.mk)

# Include Fox flags
$(call inherit-product, device/infinix/X6851B/fox.mk)

# Product Specifics
PRODUCT_NAME := twrp_X6851B
PRODUCT_DEVICE := X6851B
PRODUCT_BRAND := Infinix
PRODUCT_MODEL := Infinix Note 40 Pro+ 5G
PRODUCT_MANUFACTURER := INFINIX

PRODUCT_GMS_CLIENTID_BASE := android-transsion
