from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64


def pad(data):
    padding_length = AES.block_size - (len(data) % AES.block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

# Function to encrypt data
def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data))
    iv = base64.b64encode(cipher.iv).decode('utf-8').rstrip('+')
    encrypted_data = base64.b64encode(encrypted_data).decode('utf-8').rstrip('+')

    return iv, encrypted_data

# Function to decrypt data
def decrypt(iv, encrypted_data, key):
    iv = base64.b64decode(iv)
    encrypted_data = base64.b64decode(encrypted_data)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    padding_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_length]
    return decrypted_data.decode('utf-8')