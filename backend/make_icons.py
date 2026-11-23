# Generates the app icons (icon-192.png, icon-512.png) into backend/public
import os, glob
from PIL import Image, ImageDraw, ImageFont

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")
fonts = glob.glob("/usr/share/fonts/**/DejaVuSans-Bold.ttf", recursive=True) + glob.glob("/usr/share/fonts/**/*Bold*.ttf", recursive=True)
for s in (192, 512):
    im = Image.new("RGB", (s, s))
    px = im.load()
    a, b = (0x1d, 0x6f, 0xd8), (0x22, 0xb8, 0xcf)
    for y in range(s):
        for x in range(s):
            t = (x + y) / (2 * s)
            px[x, y] = tuple(int(a[i] * (1 - t) + b[i] * t) for i in range(3))
    d = ImageDraw.Draw(im)
    f = ImageFont.truetype(fonts[0], int(s * 0.36)) if fonts else ImageFont.load_default()
    bb = d.textbbox((0, 0), "DS", font=f)
    d.text(((s - (bb[2] - bb[0])) / 2 - bb[0], (s - (bb[3] - bb[1])) / 2 - bb[1]), "DS", font=f, fill="white")
    im.save(os.path.join(out, f"icon-{s}.png"))
print("ICONS_OK")
