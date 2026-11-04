
# Diffie-Hellman Key Exchange with MITM Attack

def generate_key(private, public, prime):
    return pow(public, private, prime)


# Public values shared by everyone
p = 23
g = 5

# Private keys of Alice and Bob
a = 6
b = 15

# Eve's private keys for the two intercepted connections
e1 = 7
e2 = 9

# Alice and Bob generate public keys
A = pow(g, a, p)
B = pow(g, b, p)

print("Prime (p):", p)
print("Generator (g):", g)

print("\n--- Normal Diffie-Hellman ---")
print("Alice sends:", A)
print("Bob sends:", B)

alice_key = generate_key(a, B, p)
bob_key = generate_key(b, A, p)

print("Alice's shared key:", alice_key)
print("Bob's shared key:", bob_key)
print("Keys match:", alice_key == bob_key)

print("\n--- MITM Attack by Eve ---")

# Eve intercepts Alice's public key and sends her own to Bob
E1 = pow(g, e1, p)

# Eve intercepts Bob's public key and sends her own to Alice
E2 = pow(g, e2, p)

print("Eve sends to Alice:", E2)
print("Eve sends to Bob:", E1)

# Alice and Bob unknowingly establish keys with Eve
alice_eve_key = pow(E2, a, p)
bob_eve_key = pow(E1, b, p)

# Eve computes the corresponding keys
eve_alice_key = pow(A, e2, p)
eve_bob_key = pow(B, e1, p)

print("Alice's key with Eve:", alice_eve_key)
print("Eve's key with Alice:", eve_alice_key)
print("Bob's key with Eve:", bob_eve_key)
print("Eve's key with Bob:", eve_bob_key)

print("Alice-Eve keys match:",
      alice_eve_key == eve_alice_key)
print("Bob-Eve keys match:",
      bob_eve_key == eve_bob_key)

print("\nEve can establish separate keys with both parties.")
print("Without authentication, Alice and Bob cannot detect Eve.")
