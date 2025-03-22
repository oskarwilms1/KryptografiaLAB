import argparse
from collections import Counter, defaultdict

def prepare_text(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        text = f.read().lower()

    # Remove non-alphabetic characters
    prepared_text = ''.join(filter(str.islower, text))

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(prepared_text)

def load_text(file):
    with open(file, 'r', encoding='utf-8') as f:
        return f.read().strip()

def save_text(file, text):
    with open(file, 'w', encoding='utf-8') as f:
        f.write(text)

def vigenere_encrypt(plaintext, key):
    key_length = len(key)
    encrypted = []

    for i, char in enumerate(plaintext):
        if char.islower():
            shifted = (ord(char) - ord('a') + ord(key[i % key_length]) - ord('a')) % 26
            encrypted.append(chr(shifted + ord('a')))

    return ''.join(encrypted)

def vigenere_decrypt(ciphertext, key):
    key_length = len(key)
    decrypted = []

    for i, char in enumerate(ciphertext):
        if char.islower():
            shifted = (ord(char) - ord('a') - (ord(key[i % key_length]) - ord('a'))) % 26
            decrypted.append(chr(shifted + ord('a')))

    return ''.join(decrypted)

def coincidence_index(text):
    length = len(text)
    if length == 0:
        return 0.0
    frequencies = defaultdict(int)
    for char in text:
        frequencies[char] += 1
    total = sum(count * (count - 1) for count in frequencies.values())
    return (total / (length * (length - 1))) if length > 1 else 0.0

def find_key_length(ciphertext, max_length=20):
    best_length = 1
    best_score = 0.0
    for length in range(1, max_length + 1):
        groups = ['' for _ in range(length)]
        for i, char in enumerate(ciphertext):
            groups[i % length] += char
        average_ic = sum(coincidence_index(group) for group in groups) / length
        if average_ic > best_score:
            best_score = average_ic
            best_length = length
    return best_length

def find_key(ciphertext, key_length):
    key = []
    for i in range(key_length):
        group = ciphertext[i::key_length]
        best_char = 'a'
        best_score = -1
        for shift in range(26):
            decrypted_group = ''.join(chr(((ord(char) - ord('a') - shift) % 26) + ord('a')) for char in group)
            score = 0
            for char in decrypted_group:
                score += letter_frequencies.get(char, 0)
            if score > best_score:
                best_score = score
                best_char = chr(shift + ord('a'))
        key.append(best_char)
    return ''.join(key).strip()

def cryptanalysis(ciphertext):
    key_length = find_key_length(ciphertext)
    key = find_key(ciphertext, key_length)
    for i in range(1, len(key)):
        if key.startswith(key[i:]):
            key = key[:i]
            break
    return key

# Frequency of letters in the English language
letter_frequencies = {
    'a': 0.081, 'b': 0.015, 'c': 0.028, 'd': 0.043,
    'e': 0.127, 'f': 0.022, 'g': 0.020, 'h': 0.061,
    'i': 0.070, 'j': 0.002, 'k': 0.008, 'l': 0.040,
    'm': 0.024, 'n': 0.067, 'o': 0.075, 'p': 0.019,
    'q': 0.001, 'r': 0.060, 's': 0.063, 't': 0.091,
    'u': 0.028, 'v': 0.010, 'w': 0.024, 'x': 0.002,
    'y': 0.020, 'z': 0.001
}

def manage_parses():
    parser = argparse.ArgumentParser()

    # Add arguments for various operations
    parser.add_argument('-p', action='store_true')  # Prepare text
    parser.add_argument('-e', action='store_true')  # Encrypt
    parser.add_argument('-d', action='store_true')  # Decrypt
    parser.add_argument('-k', action='store_true')  # Key discovery

    args = parser.parse_args()

    if args.p:
        prepare_text('orig.txt', 'plain.txt')
    
    if args.e:
        plaintext = load_text('plain.txt')
        key = load_text('key.txt')
        encrypted = vigenere_encrypt(plaintext, key)
        save_text('crypto.txt', encrypted)
   
    if args.d:
        ciphertext = load_text('crypto.txt')
        key = load_text('key.txt')
        decrypted = vigenere_decrypt(ciphertext, key)
        save_text('decrypt.txt', decrypted)
    
    if args.k:
        ciphertext = load_text('crypto.txt')
        probable_length = find_key_length(ciphertext)
        print(f'Probable key length: {probable_length}')
        found_key = find_key(ciphertext, probable_length)
        print(f'Found key: {found_key}')
        save_text('key-found.txt', found_key)
        decrypted = vigenere_decrypt(ciphertext,found_key)
        save_text('decrypt.txt',decrypted)

def main():
    manage_parses()

if __name__ == "__main__":
    main()