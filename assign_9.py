
from cryptography.fernet import Fernet

# Generate secret key
key = Fernet.generate_key()
cipher = Fernet(key)

print("Secret Key:", key.decode())

# Read image
with open("image.jpg", "rb") as file:
    image = file.read()

# Encrypt image
encrypted = cipher.encrypt(image)

with open("encrypted_image.txt", "wb") as file:
    file.write(encrypted)

print("Image encrypted successfully.")

# Decrypt image
with open("encrypted_image.txt", "rb") as file:
    encrypted_data = file.read()

try:
    decrypted = cipher.decrypt(encrypted_data)

    with open("decrypted_image.jpg", "wb") as file:
        file.write(decrypted)

    print("Image decrypted successfully.")

except Exception:
    print("Decryption failed! Image was modified or key is incorrect.")
