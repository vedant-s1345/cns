
def rotate_left(value, shift):
    shift %= 8
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def rotate_right(value, shift):
    shift %= 8
    return ((value >> shift) | (value << (8 - shift))) & 0xFF


def generate_key_stream(key, length):
    key_bytes = key.encode("utf-8")
    if not key_bytes:
        raise ValueError("Key cannot be empty")

    stream = []

    for i in range(length):
        k = key_bytes[i % len(key_bytes)]
        dynamic_key = (k + i * 17) % 256
        stream.append(dynamic_key)

    return stream


def encrypt(plaintext, key):
    data = plaintext.encode("utf-8")
    key_stream = generate_key_stream(key, len(data))

    encrypted = bytearray()

    for i, byte in enumerate(data):
        x = byte ^ key_stream[i]
        shift = (i % 7) + 1
        encrypted.append(rotate_left(x, shift))

    return encrypted.hex()


def decrypt(ciphertext, key):
    encrypted = bytes.fromhex(ciphertext)
    key_stream = generate_key_stream(key, len(encrypted))

    decrypted = bytearray()

    for i, byte in enumerate(encrypted):
        shift = (i % 7) + 1
        x = rotate_right(byte, shift)
        original = x ^ key_stream[i]
        decrypted.append(original)

    return decrypted.decode("utf-8")


# Main program
print("CUSTOM ENCRYPTION AND DECRYPTION SYSTEM")

message = input("Enter plaintext: ")
secret_key = input("Enter secret key: ")

ciphertext = encrypt(message, secret_key)

print("\nEncrypted Ciphertext:", ciphertext)

try:
    original_message = decrypt(ciphertext, secret_key)
    print("Decrypted Plaintext:", original_message)
except UnicodeDecodeError:
    print("Decryption failed. Incorrect key or corrupted ciphertext.")
