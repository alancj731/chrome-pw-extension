#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_dir"

magick -background none store-assets/listing-base.svg screenshots/password-vault.png \
  -geometry +746+114 -compose over -composite \
  -depth 8 PNG24:store-assets/listing-screenshot-1280x800.png
magick -background none store-assets/promo.svg \
  -depth 8 PNG24:store-assets/promo-440x280.png
