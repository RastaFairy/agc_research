#!/bin/sh
set -eu
export VK_DRIVER_FILES=/usr/lib/chromium/vk_swiftshader_icd.json
exec /mnt/data/agc_ps5_stage30a/vk_icd_candidate_probe
