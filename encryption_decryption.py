import sys
import math

# =============================================================================
#  HELPER FUNCTIONS: Math & Text Processing
# =============================================================================

def clean_text(text):
    """
    Normalizes input text:
    - Converts to UPPERCASE.
    - Removes all non-alphabetic characters (spaces, numbers, punctuation).
    
    Args:
        text (str): The raw input string.
        
    Returns:
        str: The cleaned, uppercase string containing only A-Z.
    """
    return "".join(c for c in text.upper() if c.isalpha())

def char_to_num(c):
    """Converts a character (A-Z) to an integer (0-25)."""
    return ord(c) - ord('A')

def num_to_char(n):
    """Converts an integer (0-25) to a character (A-Z)."""
    return chr((n % 26) + ord('A'))

def mod_inverse(a, m):
    """
    Computes the modular multiplicative inverse of a modulo m.
    Returns x such that (a * x) % m == 1.
    Raises ValueError if a and m are not coprime.
    """
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def gcd(a, b):
    """Returns the greatest common divisor of a and b."""
    return math.gcd(a, b)

# =============================================================================
#  1. CAESAR CIPHER
# =============================================================================

def encrypt_caesar(plaintext, k):
    """
    Encrypts text using Caesar Cipher.
    C = (P + k) mod 26
    """
    cleaned = clean_text(plaintext)
    ciphertext = []
    for char in cleaned:
        p_val = char_to_num(char)
        c_val = (p_val + k) % 26
        ciphertext.append(num_to_char(c_val))
    return "".join(ciphertext)

def decrypt_caesar(ciphertext, k):
    """
    Decrypts text using Caesar Cipher.
    P = (C - k) mod 26
    """
    cleaned = clean_text(ciphertext)
    plaintext = []
    for char in cleaned:
        c_val = char_to_num(char)
        p_val = (c_val - k) % 26
        plaintext.append(num_to_char(p_val))
    return "".join(plaintext)

# =============================================================================
#  2. AFFINE CIPHER
# =============================================================================

def encrypt_affine(plaintext, a, b):
    """
    Encrypts using Affine Cipher.
    C = (a * P + b) mod 26
    """
    if gcd(a, 26) != 1:
        raise ValueError(f"Key 'a' ({a}) must be coprime with 26.")
    
    cleaned = clean_text(plaintext)
    ciphertext = []
    for char in cleaned:
        p_val = char_to_num(char)
        c_val = (a * p_val + b) % 26
        ciphertext.append(num_to_char(c_val))
    return "".join(ciphertext)

def decrypt_affine(ciphertext, a, b):
    """
    Decrypts using Affine Cipher.
    P = a_inv * (C - b) mod 26
    """
    if gcd(a, 26) != 1:
        raise ValueError(f"Key 'a' ({a}) must be coprime with 26.")
        
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        raise ValueError("Modular inverse for 'a' does not exist.")

    cleaned = clean_text(ciphertext)
    plaintext = []
    for char in cleaned:
        c_val = char_to_num(char)
        # Python's % operator handles negatives correctly for mod arithmetic
        p_val = (a_inv * (c_val - b)) % 26
        plaintext.append(num_to_char(p_val))
    return "".join(plaintext)

# =============================================================================
#  3. PLAYFAIR CIPHER
# =============================================================================

def create_playfair_matrix(key):
    """
    Generates the 5x5 Playfair key square using the keyword.
    Combines I/J into 'I'.
    """
    key = clean_text(key).replace("J", "I")
    matrix_chars = []
    seen = set()
    
    # Add keyword chars
    for char in key:
        if char not in seen:
            seen.add(char)
            matrix_chars.append(char)
            
    # Add remaining alphabet (excluding J)
    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in seen:
            seen.add(char)
            matrix_chars.append(char)
            
    # Reshape into 5x5 grid (list of lists)
    matrix = [matrix_chars[i:i+5] for i in range(0, 25, 5)]
    return matrix

def find_position(matrix, char):
    """Finds row and column of a char in the 5x5 matrix."""
    if char == 'J': char = 'I'
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return None

def prepare_playfair_text(text):
    """
    Prepares text for Playfair:
    1. Clean text.
    2. Replace J with I.
    3. Split into digrams, inserting 'X' between identical letters.
    4. Pad with 'X' if length is odd.
    """
    text = clean_text(text).replace("J", "I")
    result = ""
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 < len(text):
            b = text[i+1]
            if a == b:
                result += a + "X"
                i += 1 # Advance only 1 char because we inserted X
            else:
                result += a + b
                i += 2
        else:
            result += a + "X" # Pad last single char
            i += 1
    return result

def playfair_process(text, key, mode='encrypt'):
    """
    Handles both encryption and decryption for Playfair.
    mode: 'encrypt' or 'decrypt'
    """
    matrix = create_playfair_matrix(key)
    
    # For encryption, we pad/fix text. For decryption, we assume input is valid blocks.
    if mode == 'encrypt':
        processed_text = prepare_playfair_text(text)
    else:
        processed_text = clean_text(text) # Just clean, don't insert Xs
        if len(processed_text) % 2 != 0:
            return "Error: Ciphertext length must be even."

    shift = 1 if mode == 'encrypt' else -1
    result = []
    
    for i in range(0, len(processed_text), 2):
        a = processed_text[i]
        b = processed_text[i+1]
        
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)
        
        if r1 == r2: # Same Row
            new_c1 = (c1 + shift) % 5
            new_c2 = (c2 + shift) % 5
            result.append(matrix[r1][new_c1] + matrix[r2][new_c2])
        elif c1 == c2: # Same Column
            new_r1 = (r1 + shift) % 5
            new_r2 = (r2 + shift) % 5
            result.append(matrix[new_r1][c1] + matrix[new_r2][c2])
        else: # Rectangle
            result.append(matrix[r1][c2] + matrix[r2][c1])
            
    return "".join(result)

# =============================================================================
#  4. HILL CIPHER (2x2)
# =============================================================================

def get_matrix_determinant(matrix):
    """Calculates determinant of a 2x2 matrix."""
    return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]

def get_matrix_inverse_mod26(matrix):
    """
    Calculates the inverse of a 2x2 matrix modulo 26.
    Returns None if not invertible.
    """
    det = get_matrix_determinant(matrix)
    det_inv = mod_inverse(det % 26, 26)
    
    if det_inv is None:
        return None
    
    # Adjugate matrix: [[d, -b], [-c, a]]
    a, b = matrix[0][0], matrix[0][1]
    c, d = matrix[1][0], matrix[1][1]
    
    inv_matrix = [
        [(d * det_inv) % 26, (-b * det_inv) % 26],
        [(-c * det_inv) % 26, (a * det_inv) % 26]
    ]
    return inv_matrix

def mat_mult_2x2_mod26(A, B):
    """Multiply two 2x2 matrices mod 26."""
    return [
        [ (A[0][0]*B[0][0] + A[0][1]*B[1][0]) % 26,
          (A[0][0]*B[0][1] + A[0][1]*B[1][1]) % 26 ],
        [ (A[1][0]*B[0][0] + A[1][1]*B[1][0]) % 26,
          (A[1][0]*B[0][1] + A[1][1]*B[1][1]) % 26 ]
    ]


def hill_encrypt(plaintext, K):
    """
    Hill (2x2) encryption.
    - Cleans to A-Z
    - Pads with 'X' if odd length
    """
    text = clean_text(plaintext)
    if not text:
        return ""

    if len(text) % 2 == 1:
        text += 'X'

    out = []
    for i in range(0, len(text), 2):
        p1 = char_to_num(text[i])
        p2 = char_to_num(text[i+1])
        c1 = (K[0][0]*p1 + K[0][1]*p2) % 26
        c2 = (K[1][0]*p1 + K[1][1]*p2) % 26
        out.append(num_to_char(c1))
        out.append(num_to_char(c2))

    return "".join(out)


def hill_decrypt(ciphertext, K):
    """
    Hill (2x2) decryption.
    - Cleans to A-Z
    - REJECTS odd-length ciphertext (no padding)
    - Uses K inverse mod 26 internally
    """
    text = clean_text(ciphertext)
    if not text:
        return ""

    if len(text) % 2 == 1:
        raise ValueError(
            "Invalid ciphertext length for Hill decryption: "
            "after removing non-letters, the ciphertext length must be EVEN."
        )

    K_inv = get_matrix_inverse_mod26(K)
    if K_inv is None:
        raise ValueError("Hill key is not invertible mod 26; cannot decrypt.")

    out = []
    for i in range(0, len(text), 2):
        c1 = char_to_num(text[i])
        c2 = char_to_num(text[i+1])
        p1 = (K_inv[0][0]*c1 + K_inv[0][1]*c2) % 26
        p2 = (K_inv[1][0]*c1 + K_inv[1][1]*c2) % 26
        out.append(num_to_char(p1))
        out.append(num_to_char(p2))

    return "".join(out)


def input_hill_key():
    """Helper to input 2x2 matrix from user."""
    print("\n--- Enter Hill Key Matrix (2x2) ---")
    print("Format: 4 integers separated by spaces (row-wise).")
    print("Example: '3 3 2 5' represents [[3, 3], [2, 5]]")
    
    try:
        raw = input("Enter 4 integers: ").strip().split()
        if len(raw) != 4:
            print("Error: Please enter exactly 4 integers.")
            return None
        vals = [int(x) for x in raw]
        matrix = [[vals[0], vals[1]], [vals[2], vals[3]]]
        
        # Validate invertibility
        det = get_matrix_determinant(matrix)
        if gcd(det, 26) != 1:
            print(f"Error: Determinant is {det}. It is not coprime to 26.")
            print("This matrix cannot be used for decryption. Please choose another.")
            return None
            
        return matrix
    except ValueError:
        print("Error: Invalid input. Please enter integers only.")
        return None

# =============================================================================
#  5. HILL CIPHER CRACKER (Known Plaintext Attack)
# =============================================================================

def hill_attack_known_plaintext():
    """
    Known-plaintext attack for Hill (2x2):
    Tries sliding 4-letter windows (p[i:i+4], c[i:i+4]) to recover K = C * P^{-1} mod 26,
    verifies candidate keys, and prints a recovered key if found.
    """
    print("\n--- Hill Cipher Known Plaintext Attack ---")
    print("Provide matching known plaintext and ciphertext (same positions).")
    p_text = input("Enter known plaintext (>=4 letters): ")
    c_text = input("Enter corresponding ciphertext (>=4 letters): ")

    P_all = clean_text(p_text)
    C_all = clean_text(c_text)

    if len(P_all) < 4 or len(C_all) < 4:
        print("Need at least 4 letters of plaintext and ciphertext (letters only).")
        return

    min_len = min(len(P_all), len(C_all))
    if min_len < 4:
        print("Not enough overlapping letters after cleaning input.")
        return

    # Helper: build 2x2 matrix using two bigrams as columns:
    # P = [[p1, p3],
    #      [p2, p4]]
    def build_2x2_from_4chars(s4):
        return [
            [char_to_num(s4[0]), char_to_num(s4[2])],
            [char_to_num(s4[1]), char_to_num(s4[3])]
        ]

    # Try sliding windows; step=1 for robustness (also catches misaligned user snippets),
    # but we will verify strictly by re-encrypting.
    candidates = []
    for i in range(0, min_len - 3):
        p4 = P_all[i:i+4]
        c4 = C_all[i:i+4]

        P = build_2x2_from_4chars(p4)
        C = build_2x2_from_4chars(c4)

        P_inv = get_matrix_inverse_mod26(P)
        if P_inv is None:
            continue

        K = mat_mult_2x2_mod26(C, P_inv)

        # Verify on this 4-letter window (strong check)
        if hill_encrypt(p4, K) == c4:
            candidates.append((K, i, p4, c4))

    if not candidates:
        print("No valid key found from the provided snippets.")
        print("Tips:")
        print(" - Ensure plaintext and ciphertext correspond to the same positions.")
        print(" - Provide a longer known plaintext/ciphertext segment.")
        print(" - If the snippet starts mid-block, try adding/removing 1 letter to re-align.")
        return

    # Deduplicate keys (same K may appear from multiple windows)
    unique = {}
    for K, idx, p4, c4 in candidates:
        key_tuple = tuple(K[0] + K[1])
        if key_tuple not in unique:
            unique[key_tuple] = (K, idx, p4, c4)

    # Pick the first unique key
    K, idx, p4, c4 = next(iter(unique.values()))

    print("\nRecovered Key Matrix (mod 26):")
    print(f"[[{K[0][0]}, {K[0][1]}],")
    print(f" [{K[1][0]}, {K[1][1]}]]")
    print(f"Found using window starting at offset {idx}")
    print(f"Plain window : {p4}")
    print(f"Cipher window: {c4}")

    # Optional: validate on a longer overlap segment to increase confidence
    overlap_even = (min_len // 2) * 2  # largest even <= min_len
    if overlap_even >= 6:  # if we have something meaningful beyond 4
        test_p = P_all[:overlap_even]
        test_c = C_all[:overlap_even]
        generated = hill_encrypt(test_p, K)
        if generated == test_c:
            print("Validation: Key matches the first even-length overlap segment")
        else:
            print("Validation: Key matches the 4-letter window, but NOT the longer segment")
            print("This can happen if snippets are not aligned or only partially correspond.")

    # Offer decryption using recovered key
    extra_cipher = input("\nEnter ciphertext to decrypt with recovered key (or press Enter to skip): ").strip()
    if extra_cipher:
        try:
            print("Decrypted:", hill_decrypt(extra_cipher, K))
        except ValueError as e:
            print("Error:", e)

# =============================================================================
#  MAIN MENU & UI
# =============================================================================

def menu_caesar():
    print("\n--- Caesar Cipher ---")
    mode = input("Operation (E)ncrypt or (D)ecrypt? ").upper()
    try:
        key = int(input("Enter key (shift integer): "))
        text = input("Enter text: ")
        
        if mode.startswith('E'):
            print("Result:", encrypt_caesar(text, key))
        elif mode.startswith('D'):
            print("Result:", decrypt_caesar(text, key))
        else:
            print("Invalid operation.")
    except ValueError:
        print("Invalid input for key.")

def menu_affine():
    print("\n--- Affine Cipher ---")
    mode = input("Operation (E)ncrypt or (D)ecrypt? ").upper()
    try:
        print("Key is pair (a, b) for formula (ax + b).")
        a = int(input("Enter 'a' (must be coprime to 26): "))
        if gcd(a, 26) != 1:
            print(f"Error: {a} is not coprime to 26. Try 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25.")
            return
        b = int(input("Enter 'b' (integer): "))
        text = input("Enter text: ")
        
        if mode.startswith('E'):
            print("Result:", encrypt_affine(text, a, b))
        elif mode.startswith('D'):
            print("Result:", decrypt_affine(text, a, b))
        else:
            print("Invalid operation.")
    except ValueError:
        print("Invalid input.")

def menu_playfair():
    print("\n--- Playfair Cipher ---")
    mode = input("Operation (E)ncrypt or (D)ecrypt? ").upper()
    key = input("Enter keyword (e.g., 'MONARCHY'): ")
    text = input("Enter text: ")
    
    if mode.startswith('E'):
        print("Result:", playfair_process(text, key, 'encrypt'))
    elif mode.startswith('D'):
        print("Result:", playfair_process(text, key, 'decrypt'))
    else:
        print("Invalid operation.")

def menu_hill():
    print("\n--- Hill Cipher (2x2) ---")
    print("1. Encrypt")
    print("2. Decrypt")
    choice = input("Choice: ").strip()

    matrix = input_hill_key()
    if matrix is None:
        print("Key matrix is not invertible mod 26. Try a different key.")
        return

    text = input("Enter text: ")

    try:
        if choice == "1":
            print("Encrypted:", hill_encrypt(text, matrix))
        elif choice == "2":
            print("Decrypted:", hill_decrypt(text, matrix))
        else:
            print("Invalid choice.")
    except ValueError as e:
        print("Error:", e)

def main():
    while True:
        print("\n=======================================")
        print("    CRYPTOGRAPHY TOOL PROJECT")
        print("=======================================")
        print("1. Caesar Cipher")
        print("2. Affine Cipher")
        print("3. Playfair Cipher")
        print("4. Hill Cipher (2x2)")
        print("5. Hill Cipher Known-Plaintext Attack (Cracker)")
        print("0. Exit")
        
        choice = input("\nSelect an option (0-5): ")
        
        if choice == '1':
            menu_caesar()
        elif choice == '2':
            menu_affine()
        elif choice == '3':
            menu_playfair()
        elif choice == '4':
            menu_hill()
        elif choice == '5':
            hill_attack_known_plaintext()
        elif choice == '0':
            print("Exiting...")
            sys.exit()
        else:
            print("Invalid selection. Try again.")
            
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()