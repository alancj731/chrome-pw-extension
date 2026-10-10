"""Create a Chrome Web Store ZIP without the development-only manifest key."""

import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parent.parent
manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
manifest.pop("key", None)

files = [
    "popup.html",
    "popup.css",
    "popup.js",
    "vault.js",
    "sync-model.js",
    *manifest["icons"].values(),
]
archive = ROOT / "dist" / f"chromepw-{manifest['version']}.zip"
archive.parent.mkdir(parents=True, exist_ok=True)

with ZipFile(archive, "w", compression=ZIP_DEFLATED) as package:
    package.writestr("manifest.json", json.dumps(manifest, indent=2) + "\n")
    for filename in dict.fromkeys(files):
        package.write(ROOT / filename, arcname=filename)

print(archive)
