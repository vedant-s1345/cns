
import os
import json
import base64

from cryptography.hazmat.primitives.asymmetric import (
    rsa, padding
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag


# ==========================================
# STEP 1: GENERATE RSA KEY PAIRS
# ==========================================

# Alice's keys
alice_private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=3072
)
alice_public = alice_private.public_key()

# Bob's keys
bob_private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=3072
)
bob_public = bob_private.public_key()

print("RSA Key Pairs Generated Successfully")


# ==========================================
# STEP 2: HELPER FUNCTIONS
# ==========================================

def encode(data):
    return base64.b64encode(data).decode("utf-8")


def decode(data):
    return base64.b64decode(data)


def signature_data(wrapped_key, nonce, ciphertext):
    return (
        b"SECURE-IMAGE-V1"
        + wrapped_key
        + nonce
        + ciphertext
    )


# ==========================================
# STEP 3: ALICE ENCRYPTS IMAGE
# ==========================================

def encrypt_image(image_path):

    # Read original image
    with open(image_path, "rb") as file:
        image_data = file.read()

    # Generate random AES-256 key
    aes_key = AESGCM.generate_key(bit_length=256)

    # Generate unique 96-bit nonce
    nonce = os.urandom(12)

    # Encrypt image using AES-GCM
    aes = AESGCM(aes_key)

    ciphertext = aes.encrypt(
        nonce,
        image_data,
        None
    )

    # Encrypt AES key using Bob's RSA public key
    wrapped_key = bob_public.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Digitally sign encrypted package
    signature = alice_private.sign(
        signature_data(
            wrapped_key, nonce, ciphertext
        ),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Prepare encrypted package
    package = {
        "wrapped_key": encode(wrapped_key),
        "nonce": encode(nonce),
        "ciphertext": encode(ciphertext),
        "signature": encode(signature)
    }

    # Save encrypted package
    with open("encrypted_image.json", "w") as file:
        json.dump(package, file)

    print("\nImage Encrypted Successfully!")
    print("Encrypted Package: encrypted_image.json")


# ==========================================
# STEP 4: BOB VERIFIES AND DECRYPTS IMAGE
# ==========================================

def decrypt_image():

    # Read encrypted package
    with open("encrypted_image.json", "r") as file:
        package = json.load(file)

    wrapped_key = decode(package["wrapped_key"])
    nonce = decode(package["nonce"])
    ciphertext = decode(package["ciphertext"])
    signature = decode(package["signature"])

    # Verify Alice's digital signature
    try:
        alice_public.verify(
            signature,
            signature_data(
                wrapped_key, nonce, ciphertext
            ),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("\nDigital Signature Verified!")

    except InvalidSignature:
        print("\nSignature Verification Failed!")
        print("Package may have been modified.")
        return

    # Recover AES key using Bob's private key
    try:
        aes_key = bob_private.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt image using AES-GCM
        aes = AESGCM(aes_key)

        image_data = aes.decrypt(
            nonce,
            ciphertext,
            None
        )

        # Save recovered image
        with open("received_image.png", "wb") as file:
            file.write(image_data)

        print("AES Key Recovered Successfully!")
        print("Image Decrypted Successfully!")
        print("Recovered File: received_image.png")

    except (ValueError, InvalidTag):
        print("Decryption Failed!")
        print("Image integrity verification failed.")


# ==========================================
# STEP 5: MAIN PROGRAM
# ==========================================

print("\nSECURE IMAGE TRANSMISSION SYSTEM")

image_path = input("Enter image path: ")

if os.path.isfile(image_path):

    encrypt_image(image_path)

    decrypt_image()

else:
    print("Image file not found!")
