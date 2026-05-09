from __future__ import annotations

import argparse
import base64
import re
import shutil
import subprocess
import tempfile
import zlib
from pathlib import Path

import cv2
import numpy as np
from PIL import Image


CODE128_TABLE = (
    "11011001100", "11001101100", "11001100110", "10010011000", "10010001100", "10001001100",
    "10011001000", "10011000100", "10001100100", "11001001000", "11001000100", "11000100100",
    "10110011100", "10011011100", "10011001110", "10111001100", "10011101100", "10011100110",
    "11001110010", "11001011100", "11001001110", "11011100100", "11001110100", "11101101110",
    "11101001100", "11100101100", "11100100110", "11101100100", "11100110100", "11100110010",
    "11011011000", "11011000110", "11000110110", "10100011000", "10001011000", "10001000110",
    "10110001000", "10001101000", "10001100010", "11010001000", "11000101000", "11000100010",
    "10110111000", "10110001110", "10001101110", "10111011000", "10111000110", "10001110110",
    "11101110110", "11010001110", "11000101110", "11011101000", "11011100010", "11011101110",
    "11101011000", "11101000110", "11100010110", "11101101000", "11101100010", "11100011010",
    "11101111010", "11001000010", "11110001010", "10100110000", "10100001100", "10010110000",
    "10010000110", "10000101100", "10000100110", "10110010000", "10110000100", "10011010000",
    "10011000010", "10000110100", "10000110010", "11000010010", "11001010000", "11110111010",
    "11000010100", "10001111010", "10100111100", "10010111100", "10010011110", "10111100100",
    "10011110100", "10011110010", "11110100100", "11110010100", "11110010010", "11011011110",
    "11011110110", "11110110110", "10101111000", "10100011110", "10001011110", "10111101000",
    "10111100010", "11110101000", "11110100010", "10111011110", "10111101110", "11101011110",
    "11110101110", "11010000100", "11010010000", "11010011100",
)
CODE128_LOOKUP = {bits: idx for idx, bits in enumerate(CODE128_TABLE)}
CODE128_STOP = "11000111010"
TAG_PATTERN = re.compile(r"^(?P<label>.)(?P<body>[0-9A-Fa-f]{6})(?P=label)$")


def find_7zip() -> Path:
    for candidate in (
        shutil.which("7z"),
        shutil.which("7zz"),
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ):
        if candidate and Path(candidate).exists():
            return Path(candidate)
    raise RuntimeError("7-Zip not found")


def unpack_rar(archive: Path, output_dir: Path, password: str | None = None) -> None:
    tool = find_7zip()
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [str(tool), "x", "-y", f"-o{output_dir}"]
    if password is not None:
        cmd.append(f"-p{password}")
    cmd.append(str(archive))
    result = subprocess.run(cmd, text=True, capture_output=True, check=False, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(result.stdout + result.stderr)


def png_comment_text(path: Path) -> str:
    blob = path.read_bytes()
    cursor = 8
    while cursor + 12 <= len(blob):
        size = int.from_bytes(blob[cursor:cursor + 4], "big")
        kind = blob[cursor + 4:cursor + 8]
        chunk = blob[cursor + 8:cursor + 8 + size]
        if kind == b"tEXt" and chunk.startswith(b"Comment\x00"):
            return chunk.split(b"\x00", 1)[1].decode("latin1")
        cursor += size + 12
    return ""


def red_lsb_string(path: Path) -> str:
    image = Image.open(path).convert("RGB")
    packed = bytearray()
    acc = 0
    bit_count = 0
    for r, _, _ in image.getdata():
        acc = (acc << 1) | (r & 1)
        bit_count += 1
        if bit_count == 8:
            packed.append(acc)
            acc = 0
            bit_count = 0
    if not packed:
        return ""
    text_len = packed[0]
    return bytes(packed[1:1 + text_len]).decode("ascii")


def decode_code128_words(words: list[int]) -> str:
    if not words or words[0] not in (103, 104, 105):
        raise RuntimeError("bad Code128 header")
    current = {103: "A", 104: "B", 105: "C"}[words[0]]
    out: list[str] = []
    for value in words[1:-1]:
        if current == "B":
            if 0 <= value <= 95:
                out.append(chr(value + 32))
            elif value == 99:
                current = "C"
            elif value == 100:
                current = "B"
            elif value == 101:
                current = "A"
            else:
                raise RuntimeError("unsupported Code128-B symbol")
        elif current == "C":
            if 0 <= value <= 99:
                out.append(f"{value:02d}")
            elif value == 100:
                current = "B"
            elif value == 101:
                current = "A"
            else:
                raise RuntimeError("unsupported Code128-C symbol")
        else:
            raise RuntimeError("unexpected Code128-A branch")
    return "".join(out)


def decode_code128_from_png(path: Path) -> str:
    gray = Image.open(path).convert("L")
    line_y = gray.height // 2
    samples = [1 if gray.getpixel((x, line_y)) < 128 else 0 for x in range(gray.width)]
    left = next(i for i, bit in enumerate(samples) if bit)
    right = len(samples) - next(i for i, bit in enumerate(reversed(samples)) if bit)
    samples = samples[left:right]

    runs: list[tuple[int, int]] = []
    last = samples[0]
    size = 0
    for bit in samples:
        if bit == last:
            size += 1
        else:
            runs.append((last, size))
            last = bit
            size = 1
    runs.append((last, size))

    best = ""
    for modules in range(115, 130):
        module_width = len(samples) / modules
        bitstream = "".join(str(bit) * max(1, round(width / module_width)) for bit, width in runs)
        for shift in range(3):
            words: list[int] = []
            pos = shift
            valid = True
            while pos + 11 <= len(bitstream):
                token = bitstream[pos:pos + 11]
                if token == CODE128_STOP:
                    break
                idx = CODE128_LOOKUP.get(token)
                if idx is None:
                    valid = False
                    break
                words.append(idx)
                pos += 11
            if not valid:
                continue
            try:
                candidate = decode_code128_words(words)
            except RuntimeError:
                continue
            if len(candidate) > len(best):
                best = candidate
    if not best:
        raise RuntimeError(f"cannot decode barcode: {path.name}")
    return best


def collect_note_columns(workspace: Path) -> list[tuple[str, int]]:
    gathered: list[tuple[str, int]] = []
    for image_path in sorted(workspace.glob("barcode_*.png")):
        options = (
            decode_code128_from_png(image_path),
            png_comment_text(image_path),
            red_lsb_string(image_path),
        )
        chosen = None
        for item in options:
            match = TAG_PATTERN.fullmatch(item)
            if match:
                chosen = (match.group("label"), int(match.group("body"), 16))
                break
        if chosen is None:
            raise RuntimeError(f"tag not found in {image_path.name}: {options!r}")
        gathered.append(chosen)
    return gathered


def recover_password(columns: list[tuple[str, int]]) -> str:
    ordered = [value for _, value in sorted(columns, key=lambda item: item[0])]
    scale = 12
    border = 4
    canvas = np.full(((21 + 2 * border) * scale, (21 + 2 * border) * scale), 255, np.uint8)
    for y in range(21):
        src_bit = y + 3
        for x, value in enumerate(ordered):
            black = (value >> (23 - src_bit)) & 1
            top = (y + border) * scale
            left = (x + border) * scale
            canvas[top:top + scale, left:left + scale] = 0 if black else 255
    text, _, _ = cv2.QRCodeDetector().detectAndDecode(canvas)
    if not text:
        raise RuntimeError("QR reconstruction failed")
    return text


def inflate_pdf_streams(pdf_path: Path) -> list[tuple[bytes, bytes]]:
    pdf = pdf_path.read_bytes()
    streams: list[tuple[bytes, bytes]] = []
    for match in re.finditer(rb"<<(.*?)>>\s*stream\r?\n(.*?)\r?\nendstream", pdf, re.S):
        header = match.group(1)
        body = match.group(2)
        if b"/FlateDecode" in header:
            try:
                body = zlib.decompress(body)
            except zlib.error:
                pass
        streams.append((header, body))
    return streams


def read_pdf_hint(pdf_path: Path) -> str:
    for _, body in inflate_pdf_streams(pdf_path):
        for hex_blob in re.findall(rb"<([0-9A-Fa-f]{16,})>", body):
            try:
                plain = bytes.fromhex(hex_blob.decode()).decode("ascii")
            except Exception:
                continue
            if not plain.startswith("KEY+"):
                continue
            tail = plain[4:]
            suffix = re.search(r"(\d+)$", tail)
            encoded = tail if suffix is None else tail[:suffix.start()]
            digits = "" if suffix is None else suffix.group(1)
            hint = base64.b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4), validate=True).decode("ascii")
            return f"KEY+{hint}{digits}"
    raise RuntimeError("hidden PDF clue not found")


def first_embedded_gray_image(pdf_path: Path) -> Image.Image:
    for header, body in inflate_pdf_streams(pdf_path):
        if b"/Subtype/Image" not in header:
            continue
        w = re.search(rb"/Width\s+(\d+)", header)
        h = re.search(rb"/Height\s+(\d+)", header)
        if not w or not h:
            continue
        width = int(w.group(1))
        height = int(h.group(1))
        if len(body) >= width * height:
            return Image.frombytes("L", (width, height), body[:width * height])
    raise RuntimeError("embedded image not found in PDF")


def read_score_digits(pdf_path: Path) -> str:
    image = first_embedded_gray_image(pdf_path).convert("L")
    crop = np.array(image.crop((50, 390, 640, 416)))
    mask = (crop < 200).astype(np.uint8)
    count, _, stats, _ = cv2.connectedComponentsWithStats(mask, connectivity=8)

    pieces: list[tuple[int, str]] = []
    for idx in range(1, count):
        x, y, w, h, area = stats[idx]
        real_x = x + 50
        if not (100 <= real_x <= 410 and 4 <= h <= 9 and 6 <= area <= 20):
            continue
        digit = "4" if not pieces else ("1" if w <= 2 else "5")
        pieces.append((x, digit))

    text = "".join(digit for _, digit in sorted(pieces))
    if text != "4151515":
        raise RuntimeError(f"unexpected score digits: {text!r}")
    return text


def solve(archive: Path) -> str:
    base_dir = archive.parent / "misc2_feng_alt_work"
    base_dir.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix="run_", dir=base_dir))

    unpack_rar(archive, work_dir)
    columns = collect_note_columns(work_dir)
    password = recover_password(columns)

    score_dir = work_dir / "score"
    unpack_rar(work_dir / "score.rar", score_dir, password=password)
    pdf_path = score_dir / "music score.pdf"
    if not pdf_path.exists():
        raise RuntimeError("music score.pdf not extracted")

    clue = read_pdf_hint(pdf_path)
    if clue != "KEY+numberaboveline3":
        raise RuntimeError(f"unexpected PDF clue: {clue}")

    digits = read_score_digits(pdf_path)
    return f"ISCC{{{password}{digits}}}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve attachment-18feng with a rewritten pipeline")
    parser.add_argument("archive", nargs="?", default=r"d:\CTF\powershell\attachment-18feng.rar")
    args = parser.parse_args()
    archive = Path(args.archive).expanduser().resolve()
    print(solve(archive))


if __name__ == "__main__":
    main()
