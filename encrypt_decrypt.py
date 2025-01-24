import sys

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

# Constants
SALT_SIZE = 16
KEY_SIZE = 32  # 256 bits for AES-256
BLOCK_SIZE = AES.block_size


def encrypt_file(input_file, output_file, password):
    """Encrypt the file using AES-256."""
    # Generate salt and key from password using scrypt (for secure key derivation)
    salt = get_random_bytes(SALT_SIZE)
    key = scrypt(password.encode(), salt, KEY_SIZE, N=2 ** 14, r=8, p=1)

    # Create AES cipher
    cipher = AES.new(key, AES.MODE_GCM)
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Write the salt, nonce, tag, and ciphertext to the output file
    with open(output_file, 'wb') as f:
        f.write(salt)  # Write salt
        f.write(cipher.nonce)  # Write nonce (nonce = IV in GCM mode)
        f.write(tag)  # Write tag
        f.write(ciphertext)  # Write the actual encrypted content

    print(f"File encrypted successfully and saved to {output_file}")


def decrypt_file(input_file, output_file, password):
    """Decrypt the file using AES-256."""
    # Read the encrypted file
    with open(input_file, 'rb') as f:
        salt = f.read(SALT_SIZE)
        nonce = f.read(BLOCK_SIZE)
        tag = f.read(BLOCK_SIZE)
        ciphertext = f.read()

    # Derive the key from the password and salt
    key = scrypt(password.encode(), salt, KEY_SIZE, N=2 ** 14, r=8, p=1)

    # Create AES cipher for decryption
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Decrypt the ciphertext
    try:
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        print(f"File decrypted successfully and saved to {output_file}")
    except ValueError:
        print("Decryption failed. Possibly due to incorrect password or corrupted file.")


def main():
    if len(sys.argv) < 5:
        print("Usage: python encrypt_decrypt.py <encrypt/decrypt> <input_file> <output_file> <password>")
        sys.exit(1)

    action = sys.argv[1].lower()
    input_file = sys.argv[2]
    output_file = sys.argv[3]
    password = sys.argv[4]

    if action == 'encrypt':
        encrypt_file(input_file, output_file, password)
    elif action == 'decrypt':
        decrypt_file(input_file, output_file, password)
    else:
        print("Invalid action. Use 'encrypt' or 'decrypt'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
