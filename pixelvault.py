import argparse
import binascii
import hashlib
import struct
import sys
from pathlib import Path

from PIL import Image
from rich.console import Console
from rich.panel import Panel


MAGIC = b"PVLT"
OUTER_HEADER_LEN = 12  # magic (4) + encrypted_len (4) + crc32(encrypted) (4)
INNER_HEADER_LEN = 8  # message_len (4) + crc32(message) (4)


console = Console()


def _xor_crypt(data: bytes, password: str) -> bytes:
    if password is None:
        raise ValueError("Password is required")

    pw_bytes = password.encode("utf-8")
    key = hashlib.sha256(pw_bytes).digest()
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return bytes(out)


def _bytes_to_bits(data: bytes) -> list[int]:
    bits: list[int] = []
    for byte in data:
        for bit in range(7, -1, -1):
            bits.append((byte >> bit) & 1)
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("Bit length must be divisible by 8")

    out = bytearray(len(bits) // 8)
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i : i + 8]:
            byte = (byte << 1) | (b & 1)
        out[i // 8] = byte
    return bytes(out)


def _iter_rgb_values(img: Image.Image) -> list[int]:
    rgb = img.convert("RGB")
    pixels = list(rgb.getdata())
    flat: list[int] = []
    for r, g, b in pixels:
        flat.extend((r, g, b))
    return flat


def _rgb_values_to_image(values: list[int], size: tuple[int, int]) -> Image.Image:
    if len(values) % 3 != 0:
        raise ValueError("RGB flat list length must be divisible by 3")

    it = iter(values)
    pixels = list(zip(it, it, it))
    img = Image.new("RGB", size)
    img.putdata(pixels)
    return img


def hide_message(image_path: Path, message: str, password: str, output_path: Path) -> None:
    if not image_path.exists():
        raise FileNotFoundError(f"Input image not found: {image_path}")
    if image_path.suffix.lower() != ".png":
        raise ValueError("Input image must be a PNG (.png)")

    msg_bytes = message.encode("utf-8")
    msg_crc = binascii.crc32(msg_bytes) & 0xFFFFFFFF
    inner_plain = struct.pack(">II", len(msg_bytes), msg_crc) + msg_bytes

    encrypted = _xor_crypt(inner_plain, password)
    enc_crc = binascii.crc32(encrypted) & 0xFFFFFFFF
    outer = MAGIC + struct.pack(">II", len(encrypted), enc_crc) + encrypted

    bits = _bytes_to_bits(outer)

    with Image.open(image_path) as img:
        rgb_values = _iter_rgb_values(img)
        capacity_bits = len(rgb_values)
        if len(bits) > capacity_bits:
            raise ValueError(
                f"Message too large for this image. Need {len(bits)} bits, have {capacity_bits} bits."
            )

        for i, bit in enumerate(bits):
            rgb_values[i] = (rgb_values[i] & 0xFE) | bit

        out_img = _rgb_values_to_image(rgb_values, img.convert("RGB").size)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        out_img.save(output_path, format="PNG")


def extract_message(image_path: Path, password: str) -> str:
    if not image_path.exists():
        raise FileNotFoundError(f"Input image not found: {image_path}")
    if image_path.suffix.lower() != ".png":
        raise ValueError("Input image must be a PNG (.png)")

    with Image.open(image_path) as img:
        rgb_values = _iter_rgb_values(img)

    bits = [(v & 1) for v in rgb_values]

    header_bits = bits[: OUTER_HEADER_LEN * 8]
    header = _bits_to_bytes(header_bits)

    magic = header[:4]
    if magic != MAGIC:
        raise ValueError("No PixelVault data found (magic header mismatch)")

    enc_len, enc_crc = struct.unpack(">II", header[4:12])

    total_bytes = OUTER_HEADER_LEN + enc_len
    total_bits = total_bytes * 8
    if total_bits > len(bits):
        raise ValueError("Image does not contain a complete embedded payload")

    payload = _bits_to_bytes(bits[:total_bits])
    encrypted = payload[OUTER_HEADER_LEN:]

    calc_enc_crc = binascii.crc32(encrypted) & 0xFFFFFFFF
    if calc_enc_crc != enc_crc:
        raise ValueError("Embedded data appears corrupted (CRC mismatch)")

    inner_plain = _xor_crypt(encrypted, password)
    if len(inner_plain) < INNER_HEADER_LEN:
        raise ValueError("Decrypted data is incomplete")

    msg_len, msg_crc = struct.unpack(">II", inner_plain[:8])
    msg_bytes = inner_plain[8 : 8 + msg_len]

    if len(msg_bytes) != msg_len:
        raise ValueError("Decrypted message is incomplete")

    calc_msg_crc = binascii.crc32(msg_bytes) & 0xFFFFFFFF
    if calc_msg_crc != msg_crc:
        raise ValueError("Wrong password (or corrupted data)")

    return msg_bytes.decode("utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pixelvault",
        description="Hide and extract text inside PNG images using LSB steganography.",
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--hide", action="store_true", help="Hide a message in an image")
    mode.add_argument("--extract", action="store_true", help="Extract a message from an image")

    parser.add_argument("--image", required=True, help="Input PNG image path")
    parser.add_argument("--password", required=True, help="Password used for XOR encryption")

    parser.add_argument("--message", help="Message to hide (required with --hide)")
    parser.add_argument("--output", help="Output PNG image path (required with --hide)")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        image_path = Path(args.image)

        if args.hide:
            if args.message is None or args.output is None:
                parser.error("--hide requires --message and --output")

            output_path = Path(args.output)
            hide_message(image_path, args.message, args.password, output_path)
            console.print(
                Panel.fit(
                    f"Saved stego image to: [bold]{output_path}[/bold]",
                    title="PixelVault",
                    border_style="green",
                )
            )
            return 0

        if args.extract:
            msg = extract_message(image_path, args.password)
            console.print(
                Panel.fit(
                    msg,
                    title="Extracted Message",
                    border_style="cyan",
                )
            )
            return 0

        parser.error("No mode selected")

    except SystemExit:
        raise
    except Exception as e:
        console.print(
            Panel.fit(
                f"[bold]{type(e).__name__}[/bold]\n{e}",
                title="PixelVault Error",
                border_style="red",
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
