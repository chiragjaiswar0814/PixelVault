# PixelVault

## Intro
A little python script to hide text inside images using LSB manipulation.

## Why
I wanted to understand how image steganography works under the hood instead of relying on online tools. PixelVault is a simple “write bits into pixels / read bits back out” project, with a password step so the extracted bytes aren’t plain text unless you know the key.

This is **not** a replacement for real encryption. It’s a learning project about how data can be concealed in places you usually don’t look.

## Usage
### 1) Install
```bash
python -m pip install -r requirements.txt
```

### 2) Hide a message
- Input must be a PNG.
- Output is a new PNG with the message embedded.

```bash
python pixelvault.py --hide \
  --image input.png \
  --message "meet at 7 behind the library" \
  --password "correct horse battery staple" \
  --output stego.png
```

### 3) Extract a message
```bash
python pixelvault.py --extract \
  --image stego.png \
  --password "correct horse battery staple"
```

If the password is wrong (or the data is damaged), extraction will fail with an error.
