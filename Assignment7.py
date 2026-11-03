
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# --------------------------------
# STEP 1: GENERATE DSA KEY PAIR
# --------------------------------

print("DIGITAL SIGNATURE USING DSA")

# Generate private key
private_key = dsa.generate_private_key(
    key_size=2048
)

# Generate public key
public_key = private_key.public_key()

print("\nDSA Key Pair Generated Successfully")


# --------------------------------
# STEP 2: ORIGINAL MESSAGE
# --------------------------------

message = b"Government Tender Submission: Amount 500000"


# --------------------------------
# STEP 3: GENERATE DIGITAL SIGNATURE
# --------------------------------

signature = private_key.sign(
    message,
    hashes.SHA256()
)

print("\nOriginal Message:")
print(message.decode())

print("\nDigital Signature:")
print(signature.hex())


# --------------------------------
# STEP 4: VERIFY DIGITAL SIGNATURE
# --------------------------------

try:
    public_key.verify(
        signature,
        message,
        hashes.SHA256()
    )

    print("\nSignature Verification: SUCCESS")
    print("Message is authentic and unchanged.")

except InvalidSignature:
    print("\nSignature Verification: FAILED")


# --------------------------------
# STEP 5: TEST MODIFIED MESSAGE
# --------------------------------

modified_message = b"Government Tender Submission: Amount 900000"

print("\nModified Message:")
print(modified_message.decode())

try:
    public_key.verify(
        signature,
        modified_message,
        hashes.SHA256()
    )

    print("Modified Message: VERIFIED")

except InvalidSignature:
    print("Modified Message: SIGNATURE INVALID")
    print("Message integrity compromised!")


# --------------------------------
# STEP 6: TEST WRONG PUBLIC KEY
# --------------------------------

another_private_key = dsa.generate_private_key(
    key_size=2048
)

wrong_public_key = another_private_key.public_key()

try:
    wrong_public_key.verify(
        signature,
        message,
        hashes.SHA256()
    )

    print("Wrong Key Verification: SUCCESS")

except InvalidSignature:
    print("\nWrong Key Verification: FAILED")
    print("Signature rejected!")

print("\nDIGITAL SIGNATURE EXPERIMENT COMPLETED")
