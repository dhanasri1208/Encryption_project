import base64
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA

# AES Encryption
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def aes_decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext.encode())
    nonce, tag, ciphertext = ciphertext[:16], ciphertext[16:32], ciphertext[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# DES Encryption
def des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def des_decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext.encode())
    nonce, tag, ciphertext = ciphertext[:8], ciphertext[8:16], ciphertext[16:]
    cipher = DES.new(key, DES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# RSA Encryption
def rsa_encrypt(plaintext, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return base64.b64encode(cipher.encrypt(plaintext.encode())).decode()

def rsa_decrypt(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(base64.b64decode(ciphertext.encode())).decode()
