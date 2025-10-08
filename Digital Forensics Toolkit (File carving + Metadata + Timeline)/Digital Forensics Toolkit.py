from PIL import Image
from PIL.ExifTags import TAGS
import io

def get_exif(filepath):
    img = Image.open(filepath)
    exif_data = {}
    info = img._getexif()
    if info:
        for tag, value in info.items():
            decoded = TAGS.get(tag, tag)
            exif_data[decoded] = value
    return exif_data

def carve_jpeg(raw_path, out_prefix="carved_"):
    with open(raw_path, "rb") as f:
        data = f.read()
    start = 0
    idx = 0
    while True:
        s = data.find(b'\xff\xd8\xff', start)
        if s == -1:
            break
        e = data.find(b'\xff\xd9', s)
        if e == -1:
            break
        jpg = data[s:e+2]
        with open(f"{out_prefix}{idx}.jpg", "wb") as out:
            out.write(jpg)
        idx += 1
        start = e+2
