import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding

# Original by Kelly Costa (https://github.com/kellydosocorro)

# ==================================================================== #
#   Preenchimento de texto (padding)                                   #
# ==================================================================== #

# Cria a função de preenchimento do bloco com o padder
padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()

# Cria a função de remoção do preenchimento do bloco com o unpadder
unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()

# ==================================================================== #
#   Derivando a chave dada uma senha                                   #
# ==================================================================== #

def gerador_chave():

    """
        Na prática, os sistemas não utilizam senhas e sim uma posição em
        uma tabela hash associada aquela senha.
    """

    senha = bytes(input("Insira uma senha: "), 'utf-8') # Captura a senha do usuário

    salt_iv = secrets.token_bytes(8) # Gera um salt aleatório de 16 bytes

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), # Define o SHA256 como algotitmo de hash
                 length=16, # Tamanho da chave gerada
                 salt=salt_iv, # Salt aleatório gerado anteriormente
                 iterations=1000, # Numéro de iterações que ele irá realizar
                 backend=default_backend()) 

    chave = kdf.derive(senha) # Deriva a senha obtendo a chave

    return chave

# ==================================================================== #
#   3DES                                                               #
# ==================================================================== #

def Triple_DES_ECB(chave):
    return Cipher(algorithms.TripleDES(chave), modes.ECB(), backend=default_backend())

def Triple_DES_CBC(chave, iv_criptografado):   
    return Cipher(algorithms.TripleDES(chave), modes.CBC(iv_criptografado), backend=default_backend())

# ==================================================================== #
#   Fluxo principal                                                    #
# ==================================================================== #

def main():

    print("CRIPTOGRAFIA 3DES no modo CBC\n")

    # Gera a chave a partir de uma senha
    chave = gerador_chave() 
    
    # Gera o vetor de inicialização
    iv = secrets.token_bytes(8)

    # Cria a cifra com algoritmo AES no modo ECB
    cifraECB = Triple_DES_ECB(chave)

    # Instancia o método de encriptar
    encriptografa = cifraECB.encryptor()

    # Instancia o método de descriptografar
    descriptografa = cifraECB.decryptor()

    # Encriptografa o vetor de inicializaçãos
    iv_ct = encriptografa.update(iv) 

    # Definindo a cifra
    cifra = Triple_DES_CBC(chave, descriptografa.update(iv_ct))

    # Instancia o método de encriptação
    encryptor = cifra.encryptor()
    
    # Instancia o método de decriptação
    decryptor = cifra.decryptor() 
    
    texto = bytes(input("\nDigite o texto para criptografar:\n"),'utf-8')

    # Adiciona o padding (preenchimento) no texto
    texto_padder = padder.update(texto)
    texto_padder += padder.finalize()
 
    # Criptografa texto
    ct = encryptor.update(texto_padder) + encryptor.finalize() 

    # Exibindo o texto criptografado
    print("\nTEXTO CRIPTOGRAFADO COM PADDING:\n",str(ct)[2:-1])

    # Decripta o texto
    texto = decryptor.update(ct) + decryptor.finalize()

    # Remove o padding do texto
    texto_unppader = unpadder.update(texto) + unpadder.finalize()

    # Impressão do texto descriptado sem padding
    print("\nTEXTO DESCRIPTOGRAFADO:\n",str(texto_unppader)[2:-1])

main()












    
    
    



