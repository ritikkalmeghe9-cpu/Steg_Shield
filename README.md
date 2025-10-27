# Steg_Shield
🕵️‍♂️ Rambo Steganography Tool 🔐  Advanced LSB Image Steganography with AES-256 Encryption Created by Ritik Kalmeghe
==============================================================================================================================================================

📖 Overview

Rambo Steganography Tool is a powerful and interactive Python-based steganography utility that allows you to hide secret messages inside images using Least Significant Bit (LSB) encoding — optionally protected with AES-256 encryption for military-grade security.

This tool is designed for cybersecurity learners, ethical hackers, and digital forensics enthusiasts who want to explore the intersection of cryptography and steganography.
====================================================================================================================================================================================

✨ Features

✅ LSB Image Steganography — Hide text inside image pixels invisibly.
✅ AES-256 Encryption — Encrypt your secret message before embedding.
✅ Interactive CLI Interface — Professional terminal design with centered menus, animations, and banners.
✅ Cross-Platform — Works on Linux, Windows, and macOS.
✅ Secure & Efficient — Uses PBKDF2 key derivation and CBC mode for strong protection.
✅ Fun Visuals — Includes custom ASCII banner, typing effect, and spinner animation.
===========================================================================================================================================================

🧠 How It Works

Converts your text message into binary bits.

Embeds those bits into the least significant bits of image pixel values.

Optionally encrypts your message with AES-256 before embedding.

You can later extract and decrypt the message perfectly.
===========================================================================================================================================================

⚙️ Installation

Requirements

Python 3.8+
Pillow (pip install pillow)
PyCryptodome (pip install pycryptodome)
============================================================================================================================================================

Run the Tool
python3 rambo_stego.py
================================================================================================================

🚀 Usage
🧩 Encode a Message
[1] Encode a Message into an Image

Input image path → input.png

Output image path → output.png

Secret message → "This is top secret!"

Use password encryption → y

Password → mypassword

Result:
✅ Stego image saved as: output.png

🔍 Decode a Message
[2] Decode a Message from an Image

Input image path → output.png

Is it encrypted? → y

Password → mypassword

Result:
✅ Decoded Message: This is top secret
======================================================================================================================================================================

🧩 Project Structure
Rambo-Steganography-Tool/
│
├── rambo_stego.py         # Main Python script
├── README.md              # Project description
└── example/
    ├── input.png
    └── output.png

🧰 Technologies Used

🐍 Python 3

🧱 Pillow (PIL)

🔒 PyCryptodome (AES-256)

💻 ANSI Terminal Styling

⚠️ Disclaimer

This project is for educational and ethical purposes only.
Do not use this tool for illegal data concealment or unauthorized information transfer.
The author is not responsible for misuse or legal consequences.

🧑‍💻 Created By :- Ritik Kalmeghe
💼 Cybersecurity Analyst | Python Developer | Ethical Hacker
📧 [ritikkalmeghe9@gmail.com ]
🔗 LinkedIn Profile
 (https://www.linkedin.com/in/ritik-kalmeghe-75924a303/)
====================================================================================================================================================================
