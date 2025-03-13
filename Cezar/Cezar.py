import argparse


class Cezar:
    def __init__(self):
        self.text = ""
        self.text_pomocniczy = ""
        self.key = 0

    def read_file(self, filename):
        with open(filename, "r") as file:
            return file.read()

    def write_file(self, filename, content):
        with open(filename, "w") as file:
            file.write(content)

    def encrypt(self):
        with open("key.txt", "r") as file:
            self.key = int(file.read())

        return self._cipher(self.text, self.key)

    def decrypt(self):
        with open("key.txt", "r") as file:
            self.key = int(file.read())

        return self._cipher(self.text, -self.key)

    def _cipher(self, text, shift):
        result = []
        for char in text:
            if char.isupper():
                shifted = (ord(char) + shift - ord('A')) % 26 + ord('A')
                result.append(chr(shifted))
            elif char.islower():
                shifted = (ord(char) + shift - ord('a')) % 26 + ord('a')
                result.append(chr(shifted))
            else:
                result.append(char)
        return ''.join(result)

    def kryptoanaliza_jawna(self):
        def find_key():
            key_candidates = []
            for key in range(26):
                self.key = key
                decrypted = self._cipher(self.text,self.key)
                if self.text_pomocniczy in decrypted:
                    key_candidates.append(key)

            if not key_candidates:
                raise ValueError("Nie udało się znaleźć klucza.")
            
            return key_candidates[0]
        
        self.key = find_key()
        decrypted = self._cipher(self.text,self.key)
        
        return str(self.key),decrypted

    def kryptoanaliza_kryptogram(self):
        with open("decrypt.txt","w") as file:
            decrypted = ""
            for key in range(26):
                self.key = key
                decrypted = decrypted+str(key)+". " + self._cipher(self.text,self.key)+'\n'
            file.write(decrypted)





def manage_parses():    
    parser = argparse.ArgumentParser()

    parser.add_argument('-c', action='store_true')  # Cezar
    parser.add_argument('-a', action='store_true')  # Afiniczny

    parser.add_argument('-e', action='store_true')  # Szyfrowanie
    parser.add_argument('-d', action='store_true')  # Odszyfrowanie
    parser.add_argument('-j', action='store_true')  # Kryptoanaliza z tekstem jawnym
    parser.add_argument('-k', action='store_true')  # Kryptoanaliza w oparciu o kryptogram

    args = parser.parse_args()

    if args.c:
        algorithm = Cezar()
        if args.e:
            algorithm.text = algorithm.read_file("plain.txt")
            cipher_text = algorithm.encrypt()
            algorithm.write_file("crypto.txt", cipher_text)
        elif args.d:
            algorithm.text = algorithm.read_file("crypto.txt")
            plain_text = algorithm.decrypt()
            algorithm.write_file("plain.txt", plain_text)
        elif args.j:
            algorithm.text_pomocniczy = algorithm.read_file("extra.txt")
            algorithm.text = algorithm.read_file("crypto.txt")

            found,decrypted = algorithm.kryptoanaliza_jawna()

            algorithm.write_file("key-found.txt",found)
            algorithm.write_file("decrypt.txt",decrypted)
        elif args.k:
            algorithm.text = algorithm.read_file("crypto.txt")
            algorithm.kryptoanaliza_kryptogram()



def main():
    manage_parses()


if __name__ == "__main__":
    main()