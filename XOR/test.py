import argparse

def load_text(file):
    with open(file, 'r', encoding='utf-8') as f:
        return f.read()

def save_text(file, text):
    with open(file, 'w', encoding='utf-8') as f:
        f.write(text)

def prepare_text(text):
    text = text.lower()
    result = ['']  # Start with one empty string in the list
    for current_letter in text:
        if len(result[-1]) == 64:  # New line after 64 characters
            result.append('')
        if (current_letter.isalpha() or current_letter.isspace()):
            result[-1] += current_letter
    return result

def text_to_binary(text):
    result = []
    for current_letter in text:
        if current_letter != '\n':
            ascii_value = ord(current_letter)
            binary_representation = bin(ascii_value)[2:].zfill(8)
            result.append(binary_representation)
    return result

def binary_to_text(binary_strings):
    result = []
    for binary_string in binary_strings:
        letter_value = int(binary_string, 2)
        if (97 <= letter_value <= 122) or (letter_value == 32):  # Valid characters
            result.append(chr(letter_value))
        else:
            result.append('_')  # Invalid character
    return ''.join(result)

def xor(bin1, bin2):
    if len(bin1) != len(bin2):
        raise ValueError("Binary strings must be the same length")
    return ''.join(str(int(b1) ^ int(b2)) for b1, b2 in zip(bin1, bin2))

def one_time_encrypt(prepared_text, key):
    result = []
    ascii_key = text_to_binary(key)

    if len(ascii_key) < len(prepared_text):
        raise ValueError("Key must be at least as long as the prepared text.")

    for i in range(len(prepared_text)):
        line = prepared_text[i]
        if len(line) == 8:  # Each line must be 8 bits
            key_segment = ascii_key[i % len(ascii_key)]  # Wrap around the key if too short
            encrypted_line = xor(line, key_segment)
            result.append(encrypted_line)
        else:
            result.append(line)  # Handle lines that are incorrectly sized

    return result

def cryptoanalysis(text):
    result = []
    for i in range(len(text)-1):
        result.append(xor(text[i], text[i+1]))
    result = ''.join(result)
    result = [result[j:j+8] for j in range(0,len(result),8)]
    return binary_to_text(result)

def manage_parses():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', action='store_true')  # Prepare text
    parser.add_argument('-e', action='store_true')  # Encrypt
    parser.add_argument('-k', action='store_true')  # Key discovery
    args = parser.parse_args()

    if args.p:
        orig_text = load_text('orig.txt')
        prepared_text = prepare_text(orig_text)
        save_text('plain.txt', '\n'.join(prepared_text))
    
    if args.e:
        key = load_text('key.txt')
        prepared_text = load_text('plain.txt')
        ascii_text = text_to_binary(prepared_text)
        encrypted_text = one_time_encrypt(ascii_text, key)
        save_text('encrypt.txt', ''.join(encrypted_text))

    if args.k:
        text = load_text('encrypt.txt').strip().split('\n')
        decrypted_text = cryptoanalysis(text)
        save_text('decrypt.txt', decrypted_text)

def main():
    manage_parses()

if __name__ == "__main__":
    main()