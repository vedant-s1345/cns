
import time
import statistics
import secrets

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

# RSA key sizes
key_sizes = [1024, 2048, 3072, 4096]

# Message sizes in bits
message_sizes = [128, 256, 512, 1024]

# Number of repetitions
iterations = 10

print("RSA PERFORMANCE ANALYSIS")
print("=" * 75)

for key_size in key_sizes:

    key_times = []

    # Generate RSA key pair and measure time
    for _ in range(iterations):
        start = time.perf_counter()

        private_key = RSA.generate(key_size)
        public_key = private_key.publickey()

        end = time.perf_counter()
        key_times.append(end - start)

    avg_key_time = statistics.mean(key_times)

    print(f"\nRSA Key Size: {key_size} bits")
    print(f"Average Key Generation Time: "
          f"{avg_key_time:.6f} seconds")

    print("-" * 75)

    for msg_size in message_sizes:

        # OAEP-SHA256 maximum message length:
        # modulus_bytes - 2*hash_bytes - 2
        max_len = key_size // 8 - 2 * 32 - 2

        if (msg_size + 7) // 8 > max_len:
            print(f"{msg_size}-bit message: Not supported")
            continue

        encryption_times = []
        decryption_times = []

        for _ in range(iterations):

            # Generate a random message of required bit length
            message = secrets.token_bytes((msg_size + 7) // 8)

            # RSA Encryption
            encryptor = PKCS1_OAEP.new(
                public_key, hashAlgo=SHA256
            )

            start = time.perf_counter()
            ciphertext = encryptor.encrypt(message)
            end = time.perf_counter()

            encryption_times.append(end - start)

            # RSA Decryption
            decryptor = PKCS1_OAEP.new(
                private_key, hashAlgo=SHA256
            )

            start = time.perf_counter()
            decrypted = decryptor.decrypt(ciphertext)
            end = time.perf_counter()

            decryption_times.append(end - start)

            assert decrypted == message

        avg_enc = statistics.mean(encryption_times)
        avg_dec = statistics.mean(decryption_times)

        print(f"\nMessage Size: {msg_size} bits")
        print(f"Encryption Time: {avg_enc:.8f} seconds")
        print(f"Decryption Time: {avg_dec:.8f} seconds")

print("\nExperiment Completed Successfully.")
