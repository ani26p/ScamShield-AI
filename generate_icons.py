"""
generate_icons.py — Creates PNG icons for the Chrome extension.
Run once: python generate_icons.py
"""
import os, struct, zlib

def create_png(size, color_hex, out_path):
    """Create a minimal solid-color PNG without Pillow."""
    r = int(color_hex[1:3], 16)
    g = int(color_hex[3:5], 16)
    b = int(color_hex[5:7], 16)
    a = 220

    raw = b''
    for y in range(size):
        raw += b'\x00'   # filter byte
        for x in range(size):
            # Draw a rounded shield shape
            cx = size / 2
            cy = size / 2

            # Circular mask (slightly squished for shield shape)
            dx = (x - cx) / (size * 0.42)
            dy = (y - cy * 0.95) / (size * 0.48)
            dist = dx*dx + dy*dy

            if dist <= 1.0:
                raw += bytes([r, g, b, a])
            else:
                raw += bytes([5, 13, 26, 255])   # bg color

    def make_chunk(name, data):
        crc = zlib.crc32(name + data) & 0xffffffff
        return struct.pack('>I', len(data)) + name + data + struct.pack('>I', crc)

    ihdr_data = struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0)
    idat_data = zlib.compress(raw)

    png = (
        b'\x89PNG\r\n\x1a\n'
        + make_chunk(b'IHDR', ihdr_data)
        + make_chunk(b'IDAT', idat_data)
        + make_chunk(b'IEND', b'')
    )
    with open(out_path, 'wb') as f:
        f.write(png)
    print(f"  Created: {out_path}")

if __name__ == '__main__':
    icons_dir = os.path.join(os.path.dirname(__file__), 'extension', 'icons')
    os.makedirs(icons_dir, exist_ok=True)
    print("Generating extension icons…")
    for size in [16, 48, 128]:
        create_png(size, '#00ff88', os.path.join(icons_dir, f'icon{size}.png'))
    print("Done ✓")
