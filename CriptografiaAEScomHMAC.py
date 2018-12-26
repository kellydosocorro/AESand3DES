import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding

# Cria a função de preenchimento do bloco com o padder
padder = padding.PKCS7(128).padder()

# Cria a função de remoção do preenchimento do bloco com o unpadder
unpadder = padding.PKCS7(128).unpadder()

# ==================================================================== #
# Criptografia do vetor de Inicialização (ECB Mode)                    #
# ==================================================================== #

# Gera um vetor de inicialização aleatório
iv = secrets.token_bytes(16)

# -------------------------------------- #
# Gera uma chave aleatória usando PBKDF2 #
# -------------------------------------- #

# Gera um salt aleatório
salt_iv = secrets.token_bytes(16)

# Senha para ser derivada
senha_iv = b"senha1"

# Criando a operação kdf com SHA256
kdf_iv = PBKDF2HMAC(algorithm=hashes.SHA256(), # Define o SHA256 como algotitmo de hash
                 length=32, # Tamanho da chave gerada
                 salt=salt_iv, # Salt aleatório gerado anteriormente
                 iterations=1000, # Numéro de iterações que ele irá realizar
                 backend=default_backend()) # Provê métodos que serão utilizados 

# Obtendo a chave a partir da senha
chave = kdf_iv.derive(bytes(senha_iv)) # Obtém a chave real que será utilizada: uma posição da tabela hash

# Cifrador
cifraECB = Cipher(algorithms.AES(chave), modes.ECB(), backend=default_backend())

# Recebe a função de encriptar
encriptografa = cifraECB.encryptor()

# Encriptografa o vetor de inicialização
iv_ct = encriptografa.update(iv)

# Recebe a função de descriptografar
descriptografa = cifraECB.decryptor()

# ==================================================================== #
# Definição da Cifragem (CBC Mode)                                     #
# ==================================================================== #

# Algoritmo a ser utilizado: AES
# Modo de operação: CBC
# Backend = provê operações de encriptografar e desencriptografar

# -------------------------------------- #
# Gera uma chave aleatória usando PBKDF2 #
# -------------------------------------- #

# Gera um salt aleatório
salt = secrets.token_bytes(16)

# Senha para ser derivada
password = b"senha2"

# Criando a operação kdf com SHA256
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), # Define o SHA256 como algotitmo de hash
                 length=32, # Tamanho da chave gerada
                 salt=salt, # Salt aleatório gerado anteriormente
                 iterations=1000, # Numéro de iterações que ele irá realizar
                 backend=default_backend()) # Provê métodos que serão utilizados 

# Obtendo a chave a partir da senha
key = kdf.derive(bytes(password))# Obtém a chave real que será utilizada: uma posição da tabela hash

# O cifrador recebe o algoritmo AES usando a chave de 256 bits, o modo CBC usando vetor de inicialização criptografado com ECB
cifra = Cipher(algorithms.AES(key), modes.CBC(descriptografa.update(iv_ct)), backend=default_backend())

# ==================================================================== #
# Processo de Criptografia                                             #
# ==================================================================== #

encryptor = cifra.encryptor() # Definindo qual cifra será utilizada na criptografia

chave_HMAC = secrets.token_bytes(32)

h = hmac.HMAC(chave_HMAC, hashes.SHA256(), backend= default_backend())

h_teste = h.copy()

texto_simples = b"Esse texto eh um segredo nao conte a ninguem"

# Adiciona o padding
texto_padder = padder.update(texto_simples)

h.update(texto_simples)
hmac = h.finalize()

texto_padder += padder.update(hmac)

texto_padder += padder.finalize()

ct = encryptor.update(texto_padder) + encryptor.finalize() # Criptografa texto

# Exibindo o texto criptografado
print("\nTexto criptografado usando padding:\n",str(ct)[2:-1])

# Impressão do HMAC
#print("\nHmac: ", hmac)

# ==================================================================== #
# Processo de Decriptografia                                          #
# ==================================================================== #

decryptor = cifra.decryptor() # Cifra ussada
texto = decryptor.update(ct) + decryptor.finalize() # Descriptografa usando a cifra definida
texto_unppader = unpadder.update(texto) + unpadder.finalize() # Removendo o padding
texto = texto_unppader[0:len(texto_simples)] # Obtem a mensagem que vem criptografada com o MAC
hmac_confirma = texto_unppader[len(texto_simples):] # Obtem o MAC que vem criptografado com a mensagem

# Impressão do texto descriptado sem padding
print("\nTexto decriptografado:\n",str(texto)[2:-1])

h_teste.update(texto)
hmac_teste = h_teste.finalize()

# Impressão do HMAC
#print("\nHmac: ", hmac_teste)

if hmac_confirma == hmac_teste:
    print("\nMensagem autenticada")
else:
    print("\nFalha na autenticação")




