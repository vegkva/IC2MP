from Crypto.Cipher import AES
from helpers import *
from nacl.public import PrivateKey, PublicKey, SealedBox
import binascii

def decrypt_aes_nonce(encrypted):
    
    private_key_hex = "8355ed2ac7818ffd5c8f40cd0fed77d4ca76aee6fea75a728135107e98efe08f" # CHANGE THIS
    encrypted_aes_key_hex = encrypted


    # Convert hex keys to bytes
    private_key_bytes = binascii.unhexlify(private_key_hex)
    encrypted_aes_key = binascii.unhexlify(encrypted_aes_key_hex[0:160])
    encrypted_nonce = binascii.unhexlify(encrypted_aes_key_hex[160:280])

    # Load private key using PyNaCl
    private_key = PrivateKey(private_key_bytes)
    sealed_box = SealedBox(private_key)

    # Decrypt the AES key and nonce
    aes_key = sealed_box.decrypt(encrypted_aes_key)
    aes_nonce = sealed_box.decrypt(encrypted_nonce)


    return binascii.hexlify(aes_key).decode(), binascii.hexlify(aes_nonce).decode()

# Function to decrypt using AES-GCM
def decrypt_msg_gcm(key, nonce, ciphertext_hex):
    # Convert hex-encoded ciphertext to bytes
    #print("Ciphertext: ", ciphertext_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)
    aes_key = binascii.unhexlify(key)
    aes_nonce = binascii.unhexlify(nonce)
    # Extract tag and ciphertext
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
    decrypted_message = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
    #print("Decrypted: ", decrypted_message.decode('utf-8'))
    return decrypted_message.decode('utf-8')


# Function to encrypt using AES-GCM
def encrypt_msg_gcm(key, nonce, message):
    # Convert key and nonce from hex to bytes
    aes_key = binascii.unhexlify(key)
    aes_nonce = binascii.unhexlify(nonce)
    # Convert the plaintext message to bytes
    plaintext = message.encode('utf-8')
    # Initialize the AES cipher in GCM mode
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
    # Encrypt the plaintext and generate the tag
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    # Combine the ciphertext and tag and return as hex
    combined = ciphertext + tag
    ciphertext_hex = binascii.hexlify(combined).decode('utf-8')
    #print("Ciphertext (Hex): ", ciphertext_hex)
    return ciphertext_hex


def encrypt_msg(aes_key, data):
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=b'a')
    ciphertext = cipher.encrypt(data.encode())
    return ciphertext

def decrypt_msg(aes_key, ciphertext):
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=b'a')
    message = cipher.decrypt(ciphertext)
    
    return message.decode()

