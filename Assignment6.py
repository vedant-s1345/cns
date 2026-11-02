
import hashlib

# Function to calculate SHA-1 hash
def calculate_sha1(text):
    sha1_hash = hashlib.sha1(text.encode('utf-8'))
    return sha1_hash.hexdigest()


# Original message
message1 = "Hello World"

# Modified message
message2 = "Hello world1"

# Calculate SHA-1 digests
digest1 = calculate_sha1(message1)
digest2 = calculate_sha1(message2)

# Display results
print("SHA-1 MESSAGE DIGEST")

print("\nOriginal Message:", message1)
print("SHA-1 Digest:", digest1)

print("\nModified Message:", message2)
print("SHA-1 Digest:", digest2)

# Compare hashes
if digest1 == digest2:
    print("\nBoth messages have the same digest.")
else:
    print("\nDigests are different!")
    print("Message modification detected.")


# Verify integrity
original_digest = calculate_sha1(message1)
downloaded_digest = calculate_sha1(message2)

if original_digest == downloaded_digest:
    print("\nFile Integrity Verified!")
else:
    print("\nFile Integrity Failed!")
