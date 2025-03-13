import argparse 


class Cezar():
    def __init__(self):
        self.text = ""
        self.key = 0
    def ReadFile(self,filename):
        file = open(filename,"r")
        self.text = file.read()
        file.close()
    def WriteFile(self,filename,content):
        file = open(filename,"w")
        file.write(content)
        file.close()
    def Szyfrowanie(self):
        file = open("key.txt","r")
        self.key = int(file.read())
        file.close()

        result = []

        for char in self.text:
            if char.isupper():
                shifted = (ord(char) + self.key - ord('A')) % 26 + ord('A')
                result.append(chr(shifted))

            elif char.islower():
                shifted = (ord(char) + self.key - ord('a')) % 26 + ord('a')
                result.append(chr(shifted))
            else:
                result.append(char)

        self.WriteFile("crypto.txt",''.join(result))

    def Odszyfrowanie(self):

        file = open("key.txt","r")
        self.key = int(file.read())
        file.close()

        result = []

        for char in self.text:
            if char.isupper():
                shifted = (ord(char) - self.key - ord('A')) % 26 + ord('A')
                result.append(chr(shifted))
            elif char.islower():
                shifted = (ord(char) - self.key - ord('a')) % 26 + ord('a')
                result.append(chr(shifted))
            else:
                result.append(char)

        self.WriteFile("plain.txt", ''.join(result))

    def KryptoanalizaJawna():
        pass
    def KryptoanalizaKryptogram():
        pass

def manage_parses():    
    parser = argparse.ArgumentParser()

    parser.add_argument('-c',action='store_true')   #Cezar
    parser.add_argument('-a',action='store_true')   #Afiniczny

    parser.add_argument('-e',action='store_true')   #Szyfrowanie
    parser.add_argument('-d',action='store_true')   #Odszyfrowanie
    parser.add_argument('-j',action='store_true')   #Kryptoanaliza z tekstem jawnym
    parser.add_argument('-k',action='store_true')   #Kryptoanaliza w oparciu o kryptogram


    args = parser.parse_args()

    if args.c:
        Algorytm = Cezar()
        if args.e:
            Algorytm.ReadFile("plain.txt")
            Algorytm.Szyfrowanie()
        if args.d:
            Algorytm.ReadFile("crypto.txt")
            Algorytm.Odszyfrowanie()
        


def main():

    manage_parses()



def manage_choice():
    pass









if __name__ == "__main__":
    main()