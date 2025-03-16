import argparse
from collections import Counter

def prepare_text(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        text = f.read().lower()
    
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

def frequency_analysis(text):
    frequencies = Counter(text)
    total = sum(frequencies.values())
    freq_vector = [frequencies.get(chr(i + ord('a')), 0) / total for i in range(26)]
    return freq_vector

def find_key_length(ciphertext):
    n = len(ciphertext)
    coincidences = []

    for j in range(1, min(n, 20)):
        count = sum(ciphertext[i] == ciphertext[(i + j) % n] for i in range(n - j))
        coincidences.append(count / (n - j))
    
    return coincidences.index(max(coincidences)) + 1 if coincidences else 1

def scalar_product(V, U):
    return sum(v * u for v, u in zip(V, U))

def find_key(ciphertext, key_length):
    english_freq = [
        0.082, 0.015, 0.028, 0.043, 0.127,
        0.022, 0.020, 0.061, 0.070, 0.002,
        0.008, 0.040, 0.024, 0.067, 0.075,
        0.029, 0.001, 0.060, 0.063, 0.091,
        0.028, 0.010, 0.023, 0.001, 0.020,
        0.001   
    ]

    key = []

    for i in range(key_length):
        subset = [ciphertext[j] for j in range(i, len(ciphertext), key_length)]
        freq_vector = frequency_analysis(subset)

        max_scalar = -1
        best_shift = 0
        for shift in range(26):
            shifted_vector = english_freq[shift:] + english_freq[:shift]
            product = scalar_product(freq_vector, shifted_vector)

            if product > max_scalar:
                max_scalar = product
                best_shift = shift
        
        key.append(chr(best_shift + ord('a')))
    
    return ''.join(key)

def manage_parses():    
    parser = argparse.ArgumentParser()

    parser.add_argument('-p', action='store_true')
    parser.add_argument('-e', action='store_true')
    parser.add_argument('-d', action='store_true')
    parser.add_argument('-k', action='store_true')

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
        print(f'Przypuszczalna długość klucza: {probable_length}')
        found_key = find_key(ciphertext, probable_length)
        print(f'Znaleziony klucz: {found_key}')
        save_text('key-found.txt', found_key)

def main():
    manage_parses()

if __name__ == "__main__":
    main()