import os
from Crypto.Random import get_random_bytes
from encryption import aes_encrypt, aes_decrypt, des_encrypt, des_decrypt, rsa_encrypt, rsa_decrypt
from rsa_key_management import generate_rsa_keys, save_rsa_keys, load_rsa_keys

def main():
    # Check if RSA keys exist or generate them
    if not (os.path.exists("private.pem") and os.path.exists("public.pem")):
        private_key, public_key = generate_rsa_keys()
        save_rsa_keys(private_key, public_key)
    else:
        private_key, public_key = load_rsa_keys()

    print("RSA Public Key Loaded.")

    # Text Input
    plaintext = input("Enter the text to encrypt: ")

    # AES Encryption
    aes_key = get_random_bytes(16)
    aes_ciphertext = aes_encrypt(plaintext, aes_key)
    print("\nAES Ciphertext:", aes_ciphertext)

    # DES Encryption
    des_key = get_random_bytes(8)
    des_ciphertext = des_encrypt(plaintext, des_key)
    print("DES Ciphertext:", des_ciphertext)

    # RSA Encryption
    rsa_key = get_random_bytes(64)
    rsa_ciphertext = rsa_encrypt(plaintext, public_key)
    print("RSA Ciphertext:", rsa_ciphertext)

    # Decryption
    print("\nDecrypting...")
    aes_decrypted = aes_decrypt(aes_ciphertext, aes_key)
    des_decrypted = des_decrypt(des_ciphertext, des_key)
    rsa_decrypted = rsa_decrypt(rsa_ciphertext, private_key)

    print("AES Decrypted:", aes_decrypted)
    print("DES Decrypted:", des_decrypted)
    print("RSA Decrypted:", rsa_decrypted)

if __name__ == "__main__":
    main()
