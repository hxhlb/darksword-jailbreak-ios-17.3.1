from __future__ import annotations

from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter

OUT = Path(__file__).resolve().parent
MASTER_SIZE = 1024

SIZES = {
    "AppIcon40x40@2x.png": 80,
    "AppIcon40x40@3x.png": 120,
    "AppIcon60x60@2x.png": 120,
    "AppIcon60x60@3x.png": 180,
    "AppIcon76x76.png": 76,
    "AppIcon76x76@2x.png": 152,
    "AppIcon83.5x83.5@2x.png": 167,
    "AppIcon1024.png": 1024,
}


def lerp(a: int, b: int, t: float) -> int:
    return int(a + (b - a) * t)


def gradient_background(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size))
    px = img.load()
    top = (8, 8, 12)
    mid = (48, 10, 24)
    bottom = (148, 28, 42)

    for y in range(size):
        t = y / (size - 1)
        if t < 0.6:
            k = t / 0.6
            c1, c2 = top, mid
        else:
            k = (t - 0.6) / 0.4
            c1, c2 = mid, bottom
        row = (
            lerp(c1[0], c2[0], k),
            lerp(c1[1], c2[1], k),
            lerp(c1[2], c2[2], k),
            255,
        )
        for x in range(size):
            q = x / (size - 1)
            vignette = 0.72 + 0.28 * (1 - abs(q - 0.5) * 2)
            px[x, y] = tuple(max(0, min(255, int(v * vignette))) for v in row[:3]) + (255,)
    return img


def add_lighting(base: Image.Image) -> Image.Image:
    size = base.size[0]
    glow = Image.new("RGBA", base.size, (0, 0, 0, 0))
    g = ImageDraw.Draw(glow)

    g.ellipse((size * 0.1, size * 0.08, size * 0.9, size * 0.88), fill=(255, 60, 80, 80))
    g.ellipse((size * 0.2, size * 0.1, size * 0.8, size * 0.74), fill=(255, 190, 70, 42))
    g.ellipse((size * 0.24, size * 0.6, size * 0.76, size * 0.96), fill=(18, 7, 12, 130))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=size // 14))
    return Image.alpha_composite(base, glow)


def add_border(base: Image.Image) -> Image.Image:
    size = base.size[0]
    border = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(border)
    pad = size * 0.03
    d.rounded_rectangle((pad, pad, size - pad, size - pad), radius=size * 0.22, outline=(255, 215, 120, 70), width=max(4, size // 80))
    d.rounded_rectangle((pad + size * 0.01, pad + size * 0.01, size - pad - size * 0.01, size - pad - size * 0.01), radius=size * 0.2, outline=(255, 255, 255, 24), width=max(2, size // 140))
    border = border.filter(ImageFilter.GaussianBlur(radius=size // 180))
    return Image.alpha_composite(base, border)


def sword_layer(size: int) -> Image.Image:
    layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)

    cx = size / 2
    top = size * 0.18
    bottom = size * 0.81
    blade_w = size * 0.11
    guard_y = size * 0.58
    handle_y = size * 0.69
    pommel_y = size * 0.84

    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.polygon([
        (cx, top),
        (cx + blade_w * 0.7, top + size * 0.11),
        (cx + blade_w * 0.34, guard_y),
        (cx, bottom),
        (cx - blade_w * 0.34, guard_y),
        (cx - blade_w * 0.7, top + size * 0.11),
    ], fill=(255, 90, 110, 165))
    gd.rounded_rectangle((cx - size * 0.18, guard_y - size * 0.018, cx + size * 0.18, guard_y + size * 0.018), radius=size * 0.018, fill=(255, 190, 80, 170))
    gd.rounded_rectangle((cx - size * 0.032, handle_y, cx + size * 0.032, pommel_y), radius=size * 0.03, fill=(255, 160, 80, 145))
    gd.ellipse((cx - size * 0.06, pommel_y - size * 0.02, cx + size * 0.06, pommel_y + size * 0.08), fill=(255, 205, 90, 155))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=size // 20))
    layer = Image.alpha_composite(layer, glow)

    halo = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    hd = ImageDraw.Draw(halo)
    hd.ellipse((cx - size * 0.2, size * 0.19, cx + size * 0.2, size * 0.59), outline=(255, 210, 120, 120), width=max(8, size // 64))
    halo = halo.filter(ImageFilter.GaussianBlur(radius=size // 45))
    layer = Image.alpha_composite(layer, halo)

    d.polygon([
        (cx, top),
        (cx + blade_w * 0.62, top + size * 0.11),
        (cx + blade_w * 0.26, guard_y),
        (cx, bottom),
        (cx - blade_w * 0.26, guard_y),
        (cx - blade_w * 0.62, top + size * 0.11),
    ], fill=(235, 236, 242, 255))
    d.polygon([
        (cx, top + size * 0.015),
        (cx + blade_w * 0.28, top + size * 0.16),
        (cx + blade_w * 0.11, guard_y - size * 0.02),
        (cx, bottom - size * 0.03),
    ], fill=(255, 120, 135, 110))
    d.line((cx, top + size * 0.04, cx, bottom - size * 0.05), fill=(255, 255, 255, 145), width=max(2, size // 128))

    d.rounded_rectangle((cx - size * 0.18, guard_y - size * 0.016, cx + size * 0.18, guard_y + size * 0.016), radius=size * 0.018, fill=(77, 21, 28, 255), outline=(255, 210, 120, 255), width=max(3, size // 110))
    d.rounded_rectangle((cx - size * 0.03, handle_y, cx + size * 0.03, pommel_y), radius=size * 0.025, fill=(58, 14, 21, 255), outline=(255, 196, 116, 255), width=max(3, size // 128))
    d.ellipse((cx - size * 0.052, pommel_y - size * 0.008, cx + size * 0.052, pommel_y + size * 0.072), fill=(95, 22, 27, 255), outline=(255, 212, 120, 255), width=max(3, size // 128))

    return layer


def add_shards(base: Image.Image) -> Image.Image:
    size = base.size[0]
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    shards = [
        [(size * 0.22, size * 0.26), (size * 0.31, size * 0.2), (size * 0.29, size * 0.34)],
        [(size * 0.72, size * 0.22), (size * 0.81, size * 0.3), (size * 0.69, size * 0.34)],
        [(size * 0.24, size * 0.7), (size * 0.34, size * 0.63), (size * 0.31, size * 0.78)],
        [(size * 0.69, size * 0.65), (size * 0.79, size * 0.72), (size * 0.66, size * 0.77)],
    ]
    for pts in shards:
        d.polygon(pts, fill=(255, 193, 120, 95))
    for x, y, r in [
        (0.26, 0.18, 0.018), (0.76, 0.18, 0.016), (0.18, 0.55, 0.012),
        (0.82, 0.52, 0.014), (0.31, 0.84, 0.016), (0.68, 0.82, 0.013),
    ]:
        d.ellipse((size * (x - r), size * (y - r), size * (x + r), size * (y + r)), fill=(255, 110, 120, 100))
    layer = layer.filter(ImageFilter.GaussianBlur(radius=size // 110))
    return Image.alpha_composite(base, layer)


def make_master() -> Image.Image:
    img = gradient_background(MASTER_SIZE)
    img = add_lighting(img)
    img = add_shards(img)
    img = Image.alpha_composite(img, sword_layer(MASTER_SIZE))
    img = add_border(img)
    return img


def main() -> None:
    master = make_master().convert("RGBA")
    for name, size in SIZES.items():
        resample = Image.Resampling.LANCZOS
        icon = master.resize((size, size), resample)
        icon.save(OUT / name, format="PNG")
        print(f"Generated {name} ({size}x{size})")


if __name__ == "__main__":
    main()
