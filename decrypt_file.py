from cryptography.fernet import Fernet
import os

# Step 1: Load the key
with open("secret.key", "rb") as key_file:
    key = key_file.read()

cipher = Fernet(key)

# Step 2: Specify the encrypted file
encrypted_file = "uploads/watermarked_RAG.jpg.enc"
decrypted_file = "uploads/decrypted_RAG.jpg"

# Step 3: Read and decrypt the file
with open(encrypted_file, "rb") as enc_file:
    encrypted_data = enc_file.read()

try:
    decrypted_data = cipher.decrypt(encrypted_data)

    # Step 4: Save the decrypted image
    with open(decrypted_file, "wb") as dec_file:
        dec_file.write(decrypted_data)

    print(f"✅ Decryption successful! File saved as: {decrypted_file}")

except Exception as e:
    print(f"❌ Decryption failed: {e}")
