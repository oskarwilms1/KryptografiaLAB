
#Oskar Wilms
#Kryptoanaliza: Błędne powtórzenie klucza jednorazowego

import string
import binascii
import argparse
import sys

def load_text(file):
    try:
        with open(file, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading {file}: {e}")
        return ""

def save_text(file, text):
    try:
        with open(file, 'w', encoding='utf-8', errors='replace') as f:
            f.write(text)
    except Exception as e:
        print(f"Error writing to {file}: {e}")

def text_to_binary(text):
    result = []
    for current_letter in text:
        if current_letter != '\n':
            ascii_value = ord(current_letter)
            binary_representation = bin(ascii_value)[2:].zfill(8)  # Pad to 8 bits
            result.append(binary_representation)
        else:
            result.append('\n')
    return result

def binary_to_text(binary_list):
    result = []
    for binary in binary_list:
        if binary != '\n':
            letter_value = int(binary, 2)
            result.append(chr(letter_value))
    return ''.join(result)

def xor(bin1, bin2):
    return ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(bin1, bin2))

def convert_to_lowercase_with_underscore(decrypted_part):
    return ''.join(c if 'a' <= c <= 'z' else '_' for c in decrypted_part)

def prepare_text(text):
    result = []
    text = text.lower()
    length = len(text)
    i = 0
    while i < length:
        current_letter = text[i]
        if len(result) % 65 == 0 and i != length:
            result.append('\n')
        if (current_letter.isalpha() or current_letter.isspace()) and current_letter != '\n':
            result.append(current_letter)
        i += 1
    if result and result[0] == '\n':
        result.pop(0)  # Remove leading newline if present
    return result

def one_time_encrypt(prepared_text, key):
    result = []
    i = 0
    length = len(prepared_text)
    while i < length:
        j = i % 65
        if prepared_text[i] != '\n':
            result.append(xor(prepared_text[i], key[j]))
        i += 1
    return result

def decrypt_with_xor(cipher_texts):
    decrypted_chars = []
    for i in range(len(cipher_texts)):
        for j in range(i + 1, len(cipher_texts)):
            c1 = cipher_texts[i]
            c2 = cipher_texts[j]
            if c1 and c2:
                binary_c1 = text_to_binary(c1)
                binary_c2 = text_to_binary(c2)
                combined_binary = [xor(b1, b2) for b1, b2 in zip(binary_c1, binary_c2)]
                decrypted_part = binary_to_text(combined_binary)
                processed_part = convert_to_lowercase_with_underscore(decrypted_part)
                decrypted_chars.append(processed_part)
    return ''.join(decrypted_chars)

def format_output(decrypted_text):
    return '\n'.join(decrypted_text[i:i + 64] for i in range(0, len(decrypted_text), 64))

def manage_parses():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', action='store_true', help='Prepare text')
    parser.add_argument('-e', action='store_true', help='Encrypt text')
    parser.add_argument('-k', action='store_true', help='Decrypt with XOR')


    args = parser.parse_args()

    if args.p:
        orig_text = load_text('orig.txt')
        prepared_text = prepare_text(orig_text)
        save_text('plain.txt', ''.join(prepared_text))

    if args.e:
        key = load_text('key.txt')
        prepared_text = load_text('plain.txt')
        ascii_text = text_to_binary(prepared_text)
        ascii_key = text_to_binary(key)
        encrypted_text = one_time_encrypt(ascii_text, ascii_key)
        encrypted_text = binary_to_text(encrypted_text)
        save_text('crypto.txt', ''.join(encrypted_text))

    if args.k:
        cipher_text = load_text('encrypt.txt').splitlines()
        decrypted_text = decrypt_with_xor(cipher_text)
        formatted_output = format_output(decrypted_text)
        save_text('decrypt.txt', formatted_output)

def main():
    manage_parses()

if __name__ == "__main__":
    main()
