from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64


def encrypt_pdf(pdf_path, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    
    with open(pdf_path, "rb") as pdf_file:
        pdf_data = pdf_file.read()
    encrypted_data = iv + cipher.encrypt(pdf_data)

    # Encode the encrypted data in Base64
    base64_encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
    return base64_encoded_data

key = get_random_bytes(16)
pdf_path = r""

encoded_pdf = encrypt_pdf(pdf_path, key)

print("Base64 Encoded Encrypted PDF:", encoded_pdf)
