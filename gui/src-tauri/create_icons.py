#!/usr/bin/env python3
"""Create minimal placeholder PNG icons for Tauri."""
import struct
import zlib
from pathlib import Path


def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    chunk = chunk_type + data
    crc = zlib.crc32(chunk) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk + struct.pack(">I", crc)


def create_png(path: Path, size: int, r: int = 0x1a, g: int = 0x5c, b: int = 0x9c, a: int = 0xff) -> None:
    """Create a minimal valid PNG (RGBA)."""
    raw_rows = []
    for _ in range(size):
        row = bytes([0])  # filter: none
        for _ in range(size):
            row += bytes([r, g, b, a])
        raw_rows.append(row)
    raw = b"".join(raw_rows)
    compressed = zlib.compress(raw, 9)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 6 = RGBA
    signature = b"\x89PNG\r\n\x1a\n"
    chunks = (
        png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", compressed)
        + png_chunk(b"IEND", b"")
    )
    path.write_bytes(signature + chunks)


def main() -> None:
    icons_dir = Path(__file__).parent / "icons"
    icons_dir.mkdir(exist_ok=True)

    for size in [32, 128]:
        create_png(icons_dir / f"{size}x{size}.png", size)
    create_png(icons_dir / "128x128@2x.png", 256)

    # Create .icns and .ico placeholders - use 32x32 as source for simplicity
    # Tauri may accept just PNGs; .icns/.ico are for bundling. Check tauri.conf.
    print(f"Created placeholder icons in {icons_dir}")


if __name__ == "__main__":
    main()
