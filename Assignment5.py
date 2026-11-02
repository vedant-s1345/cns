
# Diffie-Hellman Key Exchange with MITM Attack

p = 23
g = 5

# Private keys
alice_private = 6
bob_private = 15

eve_private_1 = 7
eve_private_2 = 9


def generate_public_key(private_key):
    return pow(g, private_key, p)


def generate_shared_key(public_key, private_key):
    return pow(public_key, private_key, p)


# -------- NORMAL DIFFIE-HELLMAN --------

print("NORMAL DIFFIE-HELLMAN EXCHANGE")

alice_public = generate_public_key(alice_private)
bob_public = generate_public_key(bob_private)

alice_key = generate_shared_key(bob_public, alice_private)
bob_key = generate_shared_key(alice_public, bob_private)

print("Alice Public Key:", alice_public)
print("Bob Public Key:", bob_public)
print("Alice Shared Secret:", alice_key)
print("Bob Shared Secret:", bob_key)

print("Normal Exchange Successful:",
      alice_key == bob_key)


# -------- MITM ATTACK --------

print("\nMAN-IN-THE-MIDDLE ATTACK")

# Eve generates two public keys
eve_public_1 = generate_public_key(eve_private_1)
eve_public_2 = generate_public_key(eve_private_2)

# Eve intercepts Alice's public key
# and sends her own public key to Bob
alice_received = eve_public_2
bob_received = eve_public_1

# Alice unknowingly establishes a key with Eve
alice_eve_key = generate_shared_key(
    alice_received, alice_private
)

# Bob unknowingly establishes a key with Eve
bob_eve_key = generate_shared_key(
    bob_received, bob_private
)

# Eve calculates both shared keys
eve_alice_key = generate_shared_key(
    alice_public, eve_private_2
)

eve_bob_key = generate_shared_key(
    bob_public, eve_private_1
)

print("Alice's Shared Key:", alice_eve_key)
print("Eve's Key with Alice:", eve_alice_key)

print("Bob's Shared Key:", bob_eve_key)
print("Eve's Key with Bob:", eve_bob_key)

print("\nEve knows Alice's key:",
      alice_eve_key == eve_alice_key)

print("Eve knows Bob's key:",
      bob_eve_key == eve_bob_key)


# -------- MESSAGE INTERCEPTION --------

def encrypt(message, key):
    return bytes(b ^ key for b in message.encode())


def decrypt(ciphertext, key):
    return bytes(
        b ^ key for b in ciphertext
    ).decode()


message = "Transfer amount is 1000"

# Alice encrypts using her key with Eve
ciphertext = encrypt(message, alice_eve_key)

print("\nOriginal Message:", message)
print("Encrypted Message:", ciphertext.hex())

# Eve decrypts Alice's message
intercepted = decrypt(ciphertext, eve_alice_key)

print("Eve Reads:", intercepted)

# Eve modifies the message
modified_message = "Transfer amount is 9000"

# Eve encrypts the modified message for Bob
new_ciphertext = encrypt(
    modified_message, eve_bob_key
)

# Bob decrypts using his key with Eve
received_message = decrypt(
    new_ciphertext, bob_eve_key
)

print("Bob Receives:", received_message)

print("\nMITM ATTACK SUCCESSFUL!")
