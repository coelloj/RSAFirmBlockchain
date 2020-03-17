from os import system, path
from hashlib import sha256
from random import randrange
from math import sqrt

class RSA():
    # Algoritmo de Maximo comun divisor de Euclides "EXTENDIDO" (Tomado de Wikipedia)
    @staticmethod
    def egcd(n1, n2):
        x = y = 1 # Valores temporales dentro de la recursion        
        def exgcd(a, b, x, y):
            # Caso base 
            if a == 0 :  
                x = 0
                y = 1
                return b                 
            x1 = 1
            y1 = 1 
            gcd = exgcd(b%a, a, x1, y1) # Llamada recursiva
            x = y1 - (b/a) * x1 
            y = x1 
            return gcd 
        # Rellamada a una funcion para la recursion
        return exgcd(n1, n2, x, y)
    
    # Metrodo del cifrado cumpliendo que c = m**e(mod(n)) /Tomado de Wikipedia/
    @classmethod
    def encrypt(cls, inputMessageInClear, publicKey, module):
        payload = [ord(letter) for letter in inputMessageInClear] #Se crea una lista con el contenido del mensaje
        outputMessageEncrypted = "".join([chr(letter**publicKey % module) for letter in payload]) # Se opera c = m**e(mod(n))
        return outputMessageEncrypted
    
    # Metrodo del cifrado cumpliendo que m = c**d(mod(n)) /Tomado de Wikipedia/
    @classmethod
    def decrypt(cls, inputMessageEncrypted, privateKey, module):
        payload = [ord(letter) for letter in inputMessageEncrypted]
        outputMessageInClear = "".join([chr(letter**privateKey % module) for letter in payload])
        return outputMessageInClear

    # Metodo para generar las llaves publicas y privadas /Tomado de las laminas RSA Prof Jorge Rodrigues/
    @classmethod
    def calcKeys(cls, p, q):
        module = p * q
        phi = (p - 1) * (q - 1)

        # Calculo de la llave publica que cumpla gcd(public_key, phi) == 1
        publicKeys = []        
        for i in range(phi):
            if cls.egcd(i, phi) == 1: # Usando la virtud del algoritmo de euclides 
                publicKeys.append(i)

        # Eligo un intero de la lista como llave publica
        publicKey = publicKeys[randrange(0, len(publicKeys))]
        
        # Calculo de la llave privada que cumpla (public key * private_key - 1) % phi == 0
        privateKey = 0
        x = -1
        while x != 0:
            privateKey += 1
            x = (publicKey * privateKey - 1) % phi

        return [module, publicKey, privateKey]

# Metodo para un menu de usuario en consola
def mainMenu():
    while True:
        system("cls")
        op = 0
        print("*******Firma Electronica*******")
        print("* 1. Generar Claves           *")
        print("* 2. Firmar Documento         *")
        print("* 3. Verificar firmas         *")
        print("* 0. Salir                    *")
        print("*******************************")
        op = int(input("Seleccione la opcion: "))
        if op == 0: 
            exit()
        elif(op == 1 or op == 2 or op == 3):
            return op
        else:
            print("opcion invalida!")
            system("pause")

def keys(rsa, p, q):
    key = input("Ingrese el nombre de la llave: ")
    fPrivate = open(key+".private.key", "w")       
    fPublic = open(key+".public.key", "w")       
    keys = rsa.calcKeys(p, q)
    privateKey = str(keys[0])+","+str(keys[1])
    publicKey = str(keys[0])+","+str(keys[2])

    fPrivate.write(privateKey)
    fPublic.write(publicKey)
    fPrivate.close()
    fPublic.close()
    print("Llaves Generadas")
    print("Clave Publica (modulo, exponente): ", keys[0], keys[1])
    print("Clave Privada (modulo, exponente): ", keys[0], keys[2])
    system("pause")

def sign(rsa):
    flag = True
    name = input("Ingrese el nombre del documento a firmar: ")
    name = name + ".txt"
    if path.isfile(name):
        # Se abren los ficheros que contiene el mensaje en claro 
        fDocument = open(name,"r") 
        # Se lee el contenido del mensaje
        message = fDocument.read()
        fDocument.close()
    else:
        print("El documento no existe.")
        return False

    name = input("Ingrese el nombre de la llave: ")
    name = name + ".public.key"
    if path.isfile(name):
        # Se abren los ficheros que contiene la llave
        fKey = open(name,"r") 
        line = fKey.read().split(",")

        # Se lee la clave privada
        modKey = int(line[0])
        privKey = int(line[1])
        fKey.close()
    else:
        print("La llave no existe.")
        return False    
    
    fFirm = open("mensaje.firm","wb")  

    #Se crea un hash con el contenido del mensaje usando sha256
    firm = sha256(message.encode()).hexdigest()

    # Se cifra la firma del documento con RSA 
    firmEncrypted = rsa.encrypt(firm, privKey, modKey)

    # Guardo el Cifrado de la firma 
    fFirm.write(firmEncrypted.encode())
    fFirm.close()

    return flag

def check(rsa):
    name = input("Ingrese el nombre del documento a verificar: ")
    firm = name + ".firm"
    name = name + ".txt"
    if path.isfile(name) and path.isfile(firm):
        # Se abren los ficheros que contiene el mensaje en claro 
        fDocument = open(name,"r") 
        # Se lee el contenido del mensaje
        message = fDocument.read()
        # Abro el archivo de la firma
        fd = open("mensaje.firm","rb")
        firm = fd.read()
        
        fDocument.close()
        fd.close()
    else:
        print("El documento o la firma no existe.")
        return False

    name = input("Ingrese el nombre de la llave: ")
    name = name + ".private.key"
    if path.isfile(name):
        # Se abren los ficheros que contiene la llave
        fKey = open(name,"r") 
        line = fKey.read().split(",")

        # Se lee la clave privada 
        modKey = int(line[0])
        publKey = int(line[1])
        fKey.close()
    else:
        print("La llave no existe.")
        return False    

    #Se crea un hash con el contenido del mensaje usando sha256
    msgFirm = sha256(message.encode()).hexdigest()
    firm = firm.decode()
    decryptedFirm = rsa.decrypt(firm, publKey, modKey)

    if msgFirm == decryptedFirm:
        print("El Mensaje es Autentico")
        return True
    else:
        print("No Coinciden las firmas")
        return False

# Metodo generador de primos desde 2 hasta N
def primeGenerator(n):
    primes = list()
    primes.append(2)
    for num in range(3, n+1, 2):
        if all(num % i != 0 for i in range(2, int(num**.5 ) + 1)):
            primes.append(num)
    return primes

# main
def main():
    flagOp = True
    rsa = RSA()
    # Genero una lista de primos desde 2 hasta 500
    primes = primeGenerator(500)

    # Se elige dos primo de la lista al azar
    position = randrange(40, len(primes))
    primeA = primes[position] 
    primeB = primes[position-1]

    while flagOp:
        op = mainMenu()
        if op == 1: # Opcion Generar clave publica y privada
            system("cls")
            keys(rsa, primeA, primeB)
        elif op == 2: # Opcion Cifrado de mensaje y se genera la firma  
            system("cls")
            flag = sign(rsa) 
            if flag:
                print("Firmado")  
            else:
                print("No Firmado") 
            system("pause")
        elif op == 3: # Opcion Descifrado de Firma 
            system("cls")
            flag = check(rsa) 
            if flag:
                print("Verificado")  
            else:
                print("No Verificado") 
            system("pause")
        elif op == 0:
            flagOp = False


if __name__=="__main__":
    main()