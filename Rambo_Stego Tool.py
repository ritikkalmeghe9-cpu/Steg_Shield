#!/usr/bin/env python3
"""
Rambo Steganography Tool 
"""

import os, sys, time, struct, shutil, itertools
from typing import Optional

try:
    from PIL import Image
except ImportError:
    Image = None

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import PBKDF2
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


SALT_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITERS = 100_000
IV_SIZE = 16


def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERS)


def encrypt_data(plaintext: bytes, password: str) -> bytes:
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad_len = AES.block_size - len(plaintext) % AES.block_size
    padded = plaintext + bytes([pad_len]) * pad_len
    return salt + iv + cipher.encrypt(padded)


def decrypt_data(blob: bytes, password: str) -> bytes:
    salt = blob[:SALT_SIZE]
    iv = blob[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ct = blob[SALT_SIZE + IV_SIZE:]
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ct)
    pad_len = padded[-1]
    return padded[:-pad_len]


def _to_bitstream(data: bytes) -> str:
    return ''.join(f'{byte:08b}' for byte in data)


def _from_bitstream(bits: str) -> bytes:
    if len(bits) % 8 != 0:
        bits = bits[:-(len(bits) % 8)]
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def embed_bytes_into_image(img: Image.Image, payload: bytes) -> Image.Image:
    if img.mode not in ('RGB', 'RGBA'):
        img = img.convert('RGBA')
    pixels = list(img.getdata())
    width, height = img.size
    channels = 4 if img.mode == 'RGBA' else 3
    length_bytes = struct.pack('>I', len(payload))
    bitstream = _to_bitstream(length_bytes + payload)
    required_bits = len(bitstream)
    capacity = width * height * channels
    if required_bits > capacity:
        raise ValueError("Payload too large for this image.")
    new_pixels, bit_idx = [], 0
    for px in pixels:
        comps = list(px)
        for c in range(channels):
            if bit_idx < required_bits:
                comps[c] = (comps[c] & ~1) | int(bitstream[bit_idx])
                bit_idx += 1
        new_pixels.append(tuple(comps))
    new_img = Image.new(img.mode, img.size)
    new_img.putdata(new_pixels)
    return new_img


def extract_bytes_from_image(img: Image.Image) -> bytes:
    if img.mode not in ('RGB', 'RGBA'):
        img = img.convert('RGBA')
    pixels = list(img.getdata())
    channels = 4 if img.mode == 'RGBA' else 3
    bits = ''.join(str(px[c] & 1) for px in pixels for c in range(channels))
    length_bits = bits[:32]
    payload_len = int(length_bits, 2)
    total_bits = 32 + payload_len * 8
    payload_bits = bits[32:total_bits]
    return _from_bitstream(payload_bits)


def clear(): os.system("clear" if os.name == "posix" else "cls")


def term_size():
    try:
        cols, rows = shutil.get_terminal_size()
    except:
        cols, rows = 80, 24
    return cols, rows


def center(text): 
    cols, _ = term_size()
    return text.center(cols)


def slow_print(text, delay=0.01):
    """Print text with typing animation."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def spinner(task="Processing"):
    """Simple animated spinner during tasks."""
    for c in itertools.cycle(["⠋","⠙","⠸","⠴","⠦","⠇"]):
        sys.stdout.write(f"\r\033[93m{task}... {c}\033[0m")
        sys.stdout.flush()
        time.sleep(0.1)
        if getattr(spinner, "_stop", False):
            break
    sys.stdout.write("\r\033[92m✔ Done!\033[0m\n")


def banner(animated=True):
    clear()
    lines = [
       
        "\033[1;31m██████╗ █████╗ ███╗   ███╗██████╗  ██████╗     ███████╗████████╗███████╗ ██████╗  ██████╗\033[0m",
        "\033[1;31m██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔═══██╗    ██╔════╝╚══██╔══╝██╔════╝██╔═══██╗██╔════╝\033[0m",
        "\033[1;33m██████╔╝███████║██╔████╔██║██████╔╝██║   ██║    ███████╗   ██║   █████╗  ██║   ██║██║  ███╗\033[0m",
        "\033[1;33m██╔══██╗██╔══██║██║╚██╔╝██║██╔══██╗██║   ██║    ╚════██║   ██║   ██╔══╝  ██║   ██║██║   ██║\033[0m",
        "\033[1;36m██║  ██║██║  ██║██║ ╚═╝ ██║██████╔╝╚██████╔╝    ███████║   ██║   ███████╗╚██████╔╝╚██████╔╝\033[0m",
        "\033[1;36m╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═════╝  ╚═════╝     ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝\033[0m",

 
    ]
    print("\n")
    for l in lines:
        if animated: slow_print(center(l), 0.002)
        else: print(center(l))
    print(center("\033[1;35m💀 Advanced LSB Steganography | AES-256 Encryption 💀\033[0m"))
    print(center("\033[92mCreated by Ritik Kalmeghe | Version 3.0 | Kali Linux\033[0m"))
    print(center("─" * 70))


def print_menu():
    print()
    options = [
        ("[1]", "Encode a Message into an Image"),
        ("[2]", "Decode a Message from an Image"),
        ("[3]", "Exit")
    ]
    for key, desc in options:
        print(center(f"\033[92m{key}\033[0m {desc}"))
    print(center("─" * 70))


def centered_input(prompt):
    print(center(f"\033[96m{prompt}\033[0m"))
    cols, _ = term_size()
    pad = " " * ((cols - 50) // 2)
    return input(pad + "> ")


def encode_image(input_path, output_path, message, password=None):
    if Image is None:
        raise RuntimeError("Pillow (PIL) is required.")
    img = Image.open(input_path)
    data = message.encode('utf-8')
    if password:
        if not HAVE_CRYPTO:
            raise RuntimeError("PyCryptodome missing.")
        data = encrypt_data(data, password)

    
    import threading
    spinner._stop = False
    t = threading.Thread(target=spinner, args=("Encoding",))
    t.start()
    time.sleep(1.5)
    stego = embed_bytes_into_image(img, data)
    stego.save(output_path, format='PNG')
    spinner._stop = True
    t.join()
    print(f"\n\033[92m[+] Stego image saved as:\033[0m {output_path}")


def decode_image(input_path, password=None):
    if Image is None:
        raise RuntimeError("Pillow (PIL) is required.")
    img = Image.open(input_path)
    data = extract_bytes_from_image(img)
    if password:
        if not HAVE_CRYPTO:
            raise RuntimeError("PyCryptodome missing.")
        data = decrypt_data(data, password)
    return data.decode('utf-8', errors='replace')


def main_menu():
    while True:
        banner()
        print_menu()
        choice = centered_input("Select an option (1-3)").strip()
        if choice == "1":
            encode_flow()
        elif choice == "2":
            decode_flow()
        elif choice == "3":
            print(center("\033[91mExiting... Stay Hidden, Soldier!\033[0m"))
            time.sleep(1)
            sys.exit(0)
        else:
            input(center("Invalid choice. Press Enter to retry."))


def encode_flow():
    banner(False)
    i = centered_input("Enter input image path")
    o = centered_input("Enter output image path")
    m = centered_input("Enter secret message")
    use_pass = centered_input("Use password encryption? (y/n)").lower()
    pwd = centered_input("Enter password") if use_pass == "y" else None
    try:
        encode_image(i, o, m, pwd)
    except Exception as e:
        print(center(f"\033[91mError: {e}\033[0m"))
    input(center("Press Enter to return..."))


def decode_flow():
    banner(False)
    i = centered_input("Enter stego image path")
    use_pass = centered_input("Is it encrypted? (y/n)").lower()
    pwd = centered_input("Enter password") if use_pass == "y" else None
    try:
        msg = decode_image(i, pwd)
        print()
        print(center("\033[92mDecoded Message:\033[0m"))
        print(center(f"\033[97m{msg}\033[0m"))
    except Exception as e:
        print(center(f"\033[91mError: {e}\033[0m"))
    input(center("Press Enter to return..."))


if __name__ == "__main__":
    main_menu()
