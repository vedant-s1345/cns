# Two users are exchanging the images on an unsecured network. Design a security system to
# protect the image from any security attack while transmitting it on the network.

from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

private_key=RSA.generate(2048)
public_key=private_key.publickey()
print("RSA keys generated...\n")

aes_key=Fernet.generate_key()
cipher=Fernet(aes_key)

print("Secret key generated...")

print("Secret key: ",aes_key.decode())

with open("image.jpg","rb") as file:
    image=file.read()

encrypted=cipher.encrypt(image)

with open("encrypted_image.jpg","wb") as file:
    file.write(encrypted)

print("image encrypted Successfully... ")

# print(encrypted)

rsa_cipher=PKCS1_OAEP.new(
    public_key,
    hashAlgo=SHA256
)
encrypted_key=rsa_cipher.encrypt(aes_key)

print("Secret Key Encrypted...\n")

rsa_cipher=PKCS1_OAEP(
    private_key,
    hashAlgo=SHA256
)

decrypted_key=rsa_cipher.decrypt(encrypted_key)

print("\nkey decrypted successfuuly.....")

cipher=Fernet(decrypted_key)

with open("encrypted_image.jpg","rb") as file:
    encrypted_data=file.read()

decrypted=cipher.decrypt(encrypted_data)

with open("decrypted_file.jpg","wb")as file:
    file.write(decrypted)

print("success")