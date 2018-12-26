from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def hashFunction():
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    texto = bytes(input("Digite um texto: "),'utf-8')
    digest.update(texto)
    hash_obtido = digest.finalize()
    print(hash_obtido, "Tamanho: " , len(hash_obtido),"\n")

def main():
    i = 0
    while i < 5:
        hashFunction()
        i+=1
main()
