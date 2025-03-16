import argparse


class Cezar:
    def __init__(self):
        self.text = ""
        self.text_pomocniczy = ""
        self.key = 0

    def convert_polish_to_english(self):
        polish_to_english = str.maketrans({
        'ą': 'a', 'ć': 'c', 'ę': 'e', 'ł': 'l', 
        'ń': 'n', 'ó': 'o', 'ś': 's', 'ź': 'z', 'ż': 'z', 
        'Ą': 'A', 'Ć': 'C', 'Ę': 'E', 'Ł': 'L', 
        'Ń': 'N', 'Ó': 'O', 'Ś': 'S', 'Ź': 'Z', 'Ż': 'Z'
    })
        self.text = self.text.translate(polish_to_english)
        self.text_pomocniczy = self.text_pomocniczy.translate(polish_to_english)

    def read_file(self, filename,encoding="utf-8"):
        with open(filename, "r") as file:
            return file.read()

    def write_file(self, filename, content):
        with open(filename, "w",encoding="utf-8") as file:
            file.write(content)

    def encrypt(self):
        with open("key.txt", "r") as file:
            self.key = int(file.read(1))

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
        
        return str((-self.key)%26),decrypted

    def kryptoanaliza_kryptogram(self):
        with open("decrypt.txt","w") as file:
            decrypted = ""
            for key in range(26):
                self.key = key
                decrypted = decrypted+str(key)+". " + self._cipher(self.text,self.key)+'\n'
            file.write(decrypted)
class Afiliczny:
    def __init__(self):
        self.text = ""
        self.text_pomocniczy = ""
        self.a = 1  
        self.b = 0  
        self.a_inv = 1

    def convert_polish_to_english(self):
        polish_to_english = str.maketrans({
        'ą': 'a', 'ć': 'c', 'ę': 'e', 'ł': 'l', 
        'ń': 'n', 'ó': 'o', 'ś': 's', 'ź': 'z', 'ż': 'z', 
        'Ą': 'A', 'Ć': 'C', 'Ę': 'E', 'Ł': 'L', 
        'Ń': 'N', 'Ó': 'O', 'Ś': 'S', 'Ź': 'Z', 'Ż': 'Z'
    })
        self.text = self.text.translate(polish_to_english)
        self.text_pomocniczy=self.text_pomocniczy.translate(polish_to_english)

    def read_file(self, filename):
        with open(filename, "r",encoding="utf-8") as file:
            return file.read()

    def write_file(self, filename, content):
        with open(filename, "w",encoding="utf-8") as file:
            file.write(content)

    def encrypt(self):
        with open("key.txt", "r") as file:
            keys = file.read().split()
            self.a = int(keys[0])
            self.b = int(keys[1])

        return self._cipher(self.text, self.a, self.b)

    def decrypt(self):
        with open("key.txt", "r") as file:
            keys = file.read().split()
            self.a = int(keys[0])
            self.b = int(keys[1])
            
        self.a_inv = self._mod_inverse(self.a, 26)
        if self.a_inv is None:
            raise ValueError("Multiplicative key is not invertible.")

        return self._cipher(self.text, self.a_inv, self.b,False)

    def _cipher(self, text, a, b,encrypt = True):
        result = []
        for char in text:
            if char.isalpha():
                if char.isupper():
                    if encrypt:
                        shifted = (a * (ord(char) - ord('A')) + b) % 26 + ord('A')
                    else:
                        shifted = (a * ((ord(char) - ord('A')) - b)) % 26 + ord('A')
                else:
                    if encrypt:
                        shifted = (a * (ord(char) - ord('a')) + b) % 26 + ord('a')
                    else:
                        shifted = (a * ((ord(char) - ord('a')) - b)) % 26 + ord('a')
                result.append(chr(shifted))
            else:
                result.append(char)
        return ''.join(result)
    
    def _mod_inverse(self, a, m):
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None

    def kryptoanaliza_jawna(self):
        
        def find_keys():
            key_candidates = []
            for a in range(1, 26):
                if self._gcd(a, 26) == 1:  
                    for b in range(26):  
                        self.a = a
                        self.b = b
                        decrypted = self._cipher(self.text, self.a, self.b,False)
                        if self.text_pomocniczy in decrypted:
                            key_candidates.append((a, b))  

            if not key_candidates:
                raise ValueError("Nie udało się znaleźć klucza.")
            
            return key_candidates[0]
        
        self.a, self.b = find_keys()
        decrypted = self._cipher(self.text, self.a, self.b,False)
        
        return str((-self.a)%26)+" "+str(self.b), decrypted

    def kryptoanaliza_kryptogram(self):
        with open("decrypt.txt", "w") as file:
            decrypted = ""
            for a in range(1, 26):
                if self._gcd(a, 26) == 1: 
                    for b in range(26):  
                        self.a = a
                        self.b = b
                        decrypted_text = self._cipher(self.text, self.a, self.b,False)
                        decrypted += f"a={(-a)%26}, b={b}: " + decrypted_text + '\n'
            file.write(decrypted)

    def _gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a




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
    elif args.a:
        algorithm = Afiliczny()
    else:
        return 0
    if args.e:
        algorithm.text = algorithm.read_file("plain.txt")
        algorithm.convert_polish_to_english()
        cipher_text = algorithm.encrypt()
        algorithm.write_file("crypto.txt", cipher_text)
    elif args.d:
        algorithm.text = algorithm.read_file("crypto.txt")
        plain_text = algorithm.decrypt()
        algorithm.write_file("decrypt.txt", plain_text)
    elif args.j:
        algorithm.text_pomocniczy = algorithm.read_file("extra.txt")
        algorithm.convert_polish_to_english()
        algorithm.text = algorithm.read_file("crypto.txt")

        found,decrypted = algorithm.kryptoanaliza_jawna()
        
        algorithm.write_file("key-found.txt",found)
        algorithm.write_file("decrypt.txt",decrypted)
    elif args.k:
        algorithm.text = algorithm.read_file("crypto.txt")
        algorithm.kryptoanaliza_kryptogram()
    
    else:
        return 0


def main():
    manage_parses()


if __name__ == "__main__":
    main()