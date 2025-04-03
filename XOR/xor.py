#Oskar Wilms
#Projekt: Błędne powtórzenie klucza jednorazowego


import string
import binascii
import argparse


def load_text(file):
    with open(file, 'r', encoding='utf-8') as f:
        return f.read()

def save_text(file, text):
    with open(file, 'w', encoding='utf-8') as f:
        f.write(text)

def prepare_text(text):
    result = []
    length = len(text)
    text = text.lower()
    i = 0
    while i < length:
        current_letter = text[i]
        if len(result) % 64 == 0 and i != length:
            result.append('\n')
        if (current_letter.isalpha() or current_letter.isspace()) and current_letter != '\n':
            result.append(current_letter)
        i+=1
    if result[0] == '\n':
        result.pop(0)
    return result
def text_to_binary(text):
    result = []
    length = len(text)
    i = 0
    while i < length:
        current_letter = text[i]
        if current_letter != '\n':
            ascii_value = ord(current_letter)
            binary_representation = bin(ascii_value)[2:].zfill(8)
            
            result.append(binary_representation)
        else:
            result.append('\n')
        i+=1
    
    return result
def binary_to_text(text):
    result = []
    length = len(text)
    i = 0
    while i < length:
        current_ascii = text[i]
        if current_letter != '\n':
            letter_value = int(current_ascii,2)
            letter = chr(letter_value)
            result.append(letter)
        else:
            result.append('\n')
        i+=1
    return result
def xor(bin1,bin2):
    result = ''
    length = len(bin1)
    for i in range(len(bin1)):
        if bin1[i] != bin2[i]:
            result=result+'1'
        else:
            result=result+'0'
    return result
def one_time_encrypt(prepared_text,key):
    result = []
    i=0
    length = len(prepared_text)
    while i < length:
        j = i%64
        if prepared_text[i] != '\n':
            result.append(xor(prepared_text[i],key[j]))
        else:
            result.append('\n')
        i+=1
    return result
def cryptoanalysis(text):
    result = []
    for i in range(len(text)-1):
        result.append(xor(text[i],text[i+1]))
    result = ''.join(result)
    result = [result[j:j+8] for j in range(0,len(result),8)]
    for i in range(len(result)):
        current_value = int(result[i],2)
        if 97 <= current_value <= 122:
            result[i] = chr(current_value)
        else:
            result[i] = '_'
        if i % 64 == 0:
            result[i] = result[i]+'\n'

    return result
def manage_parses():
    parser = argparse.ArgumentParser()

    # Add arguments for various operations
    parser.add_argument('-p', action='store_true')  # Prepare text
    parser.add_argument('-e', action='store_true')  # Encrypt
    parser.add_argument('-k', action='store_true')  # Key discovery
    parser.add_argument('-t', action='store_true')  # test
    args = parser.parse_args()

    if args.p:
       orig_text = load_text('orig.txt')
       prepared_text = prepare_text(orig_text)
       save_text('plain.txt',''.join(prepared_text))
    
    if args.e:
        key = load_text('key.txt')
        prepared_text = load_text('plain.txt')
        ascii_text = text_to_binary(prepared_text)
        ascii_key = text_to_binary(key)
        encrypted_text = one_time_encrypt(ascii_text,ascii_key)
        save_text('encrypt.txt',''.join(encrypted_text))
    if args.t:
        text = load_text('encrypt.txt') 
        prepared_text= text.split('\n')
        decrypted_text = cryptoanalysis(prepared_text)
        save_text('decrypt.txt',''.join(decrypted_text))

   
    
    if args.k:
        pass


def main():
    manage_parses()

if __name__ == "__main__":
    main()