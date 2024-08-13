# Lab 4

## Crytopals SET 1

**Note** Images for cryptopals solutions are in the images folder. [Click here.](/images)

1. Convert HEX to base64
```python
#Convert hex to base64

import codecs

hex_string = input("Enter the hex string: ")
bytes_data = codecs.decode(hex_string, 'hex')

base64_data = codecs.encode(bytes_data, 'base64')
base64_string = base64_data.decode('utf-8')

print("\nThe converted base64 string is :")
print(base64_string)
```

2. 
```python
# FIXED XOR

import codecs

hex_coded = input("Enter string: ")
decoded = codecs.decode(hex_coded, 'hex')

xor_value = '686974207468652062756c6c277320657965'
xor_decoded = codecs.decode(xor_value, 'hex')

after_xor = bytes(a ^ b for a, b in zip(decoded, xor_decoded))

result = codecs.encode(after_xor, 'hex').decode()

print("Decoded value is :", decoded)
print("After XOR: ", result)
```

3. 
```python
import binascii

def bit_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def ascii_ratio(a: bytes) -> float:
    ascii_chars = set(range(97, 123)).union({32})  # ASCII range for lowercase letters and space
    n_ascii = sum(1 for x in a if x in ascii_chars)
    return n_ascii / len(a)

def text_prob(a: bytes) -> bool:
    return ascii_ratio(a) > 0.75

def main():
    hex_string = input("Enter the hex string: ")
    try:
        input_str = binascii.unhexlify(hex_string)
    except binascii.Error:
        print("Invalid hex string")
        return

    for i in range(256):
        key = bytes([i] * len(input_str))
        xored = bit_xor(input_str, key)
        if text_prob(xored):
            print(f"Key: {i},\n  Decrypted: {xored.decode('utf-8', errors='ignore')}")

if __name__ == "__main__":
    main()
```

4. 
```python
# Detect single-character XOR 
import binascii

def bit_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def ascii_ratio(a: bytes, ascii_chars: set) -> float:
    n_ascii = sum(1 for x in a if x in ascii_chars)
    return n_ascii / len(a)

def text_prob(a: bytes, ascii_chars: set) -> bool:
    return ascii_ratio(a, ascii_chars) > 0.75

def main():
    ascii_chars = set(range(97, 123)).union({32})  
    path = "challenge_4_text.txt"
    
    try:
        with open(path, "r") as file:
            for line in file:
                line = line.strip()
                try:
                    decoded = binascii.unhexlify(line)
                except binascii.Error:
                    print(f"Failed to decode hex: {line}")
                    continue

                for i in range(256):
                    key = bytes([i] * len(decoded))
                    xored = bit_xor(decoded, key)
                    if text_prob(xored, ascii_chars):
                        print(f"Key: {i}, Decrypted: {xored.decode('utf-8', errors='ignore')}")
    except FileNotFoundError:
        print(f"Failed to open file: {path}")

if __name__ == "__main__":
    main()
```

5. 
```python
# Implementing repeating-key XOR

import binascii

def bit_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def main():
    input_str = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"
    keystream = bytes([key[i % len(key)] for i in range(len(input_str))])

    xored = bit_xor(input_str, keystream)
    print(binascii.hexlify(xored).decode())

if __name__ == "__main__":
    main()
```

6. 
```python
import base64
from itertools import cycle
import os

def hamming_distance(str1: bytes, str2: bytes) -> int:
    """Calculate the Hamming distance between two byte strings."""
    assert len(str1) == len(str2), "Strings must be of the same length"
    return sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(str1, str2))

def normalized_hamming_distance(data: bytes, key_size: int) -> float:
    """Calculate the normalized Hamming distance for a given key size."""
    chunks = [data[i:i + key_size] for i in range(0, len(data), key_size)]
    num_chunks = len(chunks) - 1
    
    # Ensure all chunks being compared are of equal length
    distances = [hamming_distance(chunks[i], chunks[i + 1]) for i in range(num_chunks) if len(chunks[i]) == key_size and len(chunks[i + 1]) == key_size]
    
    # Return normalized Hamming distance
    return sum(distances) / (len(distances) * key_size)

def find_key_size(data: bytes, min_key_size: int = 2, max_key_size: int = 40) -> int:
    """Find the key size that gives the smallest normalized Hamming distance."""
    distances = []
    for key_size in range(min_key_size, max_key_size + 1):
        distance = normalized_hamming_distance(data, key_size)
        distances.append((key_size, distance))
    best_key_size = min(distances, key=lambda x: x[1])[0]
    return best_key_size

def single_byte_xor(data: bytes, key: int) -> bytes:
    """Decrypt a single-byte XOR cipher."""
    return bytes([b ^ key for b in data])

def score_english_text(text: bytes) -> float:
    """Score text based on how closely it matches typical English text."""
    character_frequencies = {
        'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442,
        'f': 0.0197881, 'g': 0.015861, 'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033,
        'k': 0.0050529, 'l': 0.033149, 'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302,
        'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.051576, 't': 0.0729357,
        'u': 0.0225134, 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984,
        'z': 0.0007836, ' ': 0.1918182
    }
    return sum(character_frequencies.get(chr(byte).lower(), 0) for byte in text)

def find_single_byte_xor_key(data: bytes) -> int:
    """Find the single-byte XOR key that produces the best English text."""
    scores = []
    for key in range(256):
        decrypted_text = single_byte_xor(data, key)
        score = score_english_text(decrypted_text)
        scores.append((key, score))
    best_key = max(scores, key=lambda x: x[1])[0]
    return best_key

def decrypt_repeating_key_xor(data: bytes, key: bytes) -> bytes:
    """Decrypt data encrypted with repeating-key XOR."""
    return bytes([b ^ k for b, k in zip(data, cycle(key))])

def break_repeating_key_xor(data: bytes) -> (bytes, bytes):
    """Break repeating-key XOR encryption."""
    key_size = find_key_size(data)
    key = bytearray()
    
    for i in range(key_size):
        block = data[i::key_size]
        key.append(find_single_byte_xor_key(block))
    
    decrypted_data = decrypt_repeating_key_xor(data, key)
    return key, decrypted_data

if __name__ == "__main__":
    # Read the file containing the base64 encoded text
    direct = os.path.dirname(__file__)
    filename = os.path.join(direct, 'challenge_6_text.txt')
    with open(filename, "r") as file:
        data = base64.b64decode(file.read())

    key, decrypted_data = break_repeating_key_xor(data)
    print(f"Key: {key.decode()}")
    print(f"Decrypted text:\n{decrypted_data.decode(errors='ignore')}")
```

7. 
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64decode

backend = default_backend()

def decrypt_aes(ciphertext: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_msg = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_msg

def main():
    key = b"YELLOW SUBMARINE"
    try:
        with open("challenge_7_text.txt", "r") as in_file:
            input_str = in_file.read().strip()
            decrypted_msg = decrypt_aes(b64decode(input_str), key)
            print(decrypted_msg.decode("utf-8"))
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
```

8. 
```python
from binascii import unhexlify

key_len = 16  # AES block size is 16 bytes

def is_prob_ecb(text: bytes) -> bool:
    """
    Determines if the given text is likely encrypted with ECB mode.
    
    :param text: The encrypted text (ciphertext).
    :return: True if the text is likely encrypted with ECB mode, False otherwise.
    """
    if len(text) % key_len != 0:
        return False
    
    # Divide the text into blocks of key_len bytes
    n_blocks = len(text) // key_len
    blocks = [text[i * key_len:(i + 1) * key_len] for i in range(n_blocks)]
    
    # Check for duplicate blocks
    return len(set(blocks)) < len(blocks)

def main():
    with open("challenge_8_text.txt", "r") as in_file:
        print("Probable ECB encoded text:")
        for line in in_file:
            line = line.strip()
            hex_text = unhexlify(line)
            if is_prob_ecb(hex_text):
                print(line)

if __name__ == "__main__":
    main()
```