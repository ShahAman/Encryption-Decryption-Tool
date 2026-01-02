# Encryption-Decryption-Tool
# Encryption/Decryption Tool & Cracker

This project implements a cryptographic tool capable of encrypting and decrypting messages using four classic cipher systems. It also includes a cryptanalysis module to crack the Hill Cipher using a Known Plaintext Attack.

## Features
* **Caesar Cipher:** Standard shift cipher.
* **Affine Cipher:** Linear function encryption ($ax + b$). Includes validation to ensure key $a$ is coprime to 26.
* **Playfair Cipher:** Digram substitution using a $5\times5$ key matrix (I/J merged).
* **Hill Cipher:** Polygraphic substitution using a $2\times2$ key matrix.
* **Hill Cipher Cracker:** A tool to recover the Key Matrix given a snippet of Plaintext and Ciphertext.

## Prerequisites
* **OS:** Windows, macOS, or Linux
* **Language:** Python 3.x
* **Libraries:** Standard Python libraries (`sys`, `math`). No external installation required.

## How to Run
1.  Ensure you have Python installed. You can check by running:
    ```bash
    python --version
    ```
2.  Clone this repository or download the `main.py` file.
3.  Open a terminal/command prompt in the project directory.
4.  Run the application:
    ```bash
    python encryption_decryption.py
    ```
    *(Note: If your system uses `python3`, type `python3 main.py`)*

## Usage Guide
1.  Upon launching, you will see a main menu with 6 options (0-5).
2.  Select **Option 1-4** for specific ciphers. You will be asked for:
    * Operation: Encrypt (E) or Decrypt (D).
    * Key: Integer(s) or String depending on the cipher.
    * Text: The message to process.
3.  Select **Option 5** for the Hill Cipher Cracker.
    * Input at least 4 characters of known Plaintext.
    * Input the corresponding 4 characters of Ciphertext.
    * The tool will attempt to calculate the Inverse Plaintext Matrix and solve for the Key.

