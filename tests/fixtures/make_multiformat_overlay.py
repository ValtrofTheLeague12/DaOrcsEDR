import struct, zipfile, io
from pathlib import Path

src = Path("a.exe")
dst = Path("logs/a_overlay_multiformat.exe")
b = bytearray(src.read_bytes())
e = struct.unpack_from("<I", b, 0x3C)[0]
nsec = struct.unpack_from("<H", b, e + 6)[0]
optsz = struct.unpack_from("<H", b, e + 20)[0]
sec = e + 24 + optsz
last = 0
for i in range(nsec):
    off = sec + i * 40
    rawsz = struct.unpack_from("<I", b, off + 16)[0]
    rawptr = struct.unpack_from("<I", b, off + 20)[0]
    last = max(last, rawptr + rawsz)

buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("payload.txt", "embedded zip inside a PE overlay\n")
zip_bytes = buf.getvalue()
png = (b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 40)
gzip = b"\x1f\x8b\x08\x00" + b"\x00" * 20

blob = zip_bytes + b"OVERLAY-MARKER" + png + b"TAIL-MARK" + gzip
out = b + blob
# keep SizeOfImage sanity: no section changes, overlay is simply trailing data
dst.write_bytes(out)
print("last_section_end=0x%x" % last)
print("file_size=%d" % len(out))
print("overlay=%d" % (len(out) - last))
print("zip_at=0x%x" % (last,))
print("png_at=0x%x" % (last + len(zip_bytes) + len(b"OVERLAY-MARKER")))
print("gzip_at=0x%x" % (len(out) - len(gzip)))
