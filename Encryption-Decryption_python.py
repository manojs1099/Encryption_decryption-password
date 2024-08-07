from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import os

# Constants
BLOCK_SIZE = 16
SALT_SIZE = 16
KEY_SIZE = 32  # 256 bits key for AES-256
ITERATIONS = 100000
CREDENTIALS_FILE = 'credentials.txt'

# Padding for AES encryption
def pad(s):
    padding = BLOCK_SIZE - len(s) % BLOCK_SIZE
    return s + (chr(padding) * padding).encode()

def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

# Encrypt data using AES
def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode()))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

# Decrypt data using AES
def decrypt(enc_data, key):
    iv = base64.b64decode(enc_data[:24])
    ct = base64.b64decode(enc_data[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct))
    return pt.decode('utf-8')

# Create key from user-specific passphrase using PBKDF2
def create_key_from_passphrase(passphrase, salt, iterations=ITERATIONS, key_size=KEY_SIZE):
    key = PBKDF2(passphrase, salt, dkLen=key_size, count=iterations)
    return key

# Save credentials with user-specific encrypted password
def save_credentials(username, password, user_passphrase, filename=CREDENTIALS_FILE):
    salt = get_random_bytes(SALT_SIZE)
    user_key = create_key_from_passphrase(user_passphrase, salt)
    encrypted_password = encrypt(password, user_key)
    print(f"Encrypted password for {username}: {encrypted_password}") 
    with open(filename, 'a') as f:
        f.write(f'{username}|{base64.b64encode(salt).decode("utf-8")}|{encrypted_password}\n')

# Load credentials and display encrypted password
def load_credentials(filename=CREDENTIALS_FILE):
    if not os.path.exists(filename):
        print("No credentials file found.")
        return
    
    with open(filename, 'r') as f:
        lines = f.readlines()
        for line in lines:
            parts = line.strip().split('|')
            if len(parts) != 3:
                print(f"Skipping invalid line: {line}")
                continue
            username, salt, enc_password = parts
            print(f'Username: {username}, Encrypted Password: {enc_password}')

# View decrypted password for a specific user
def view_password(username, user_passphrase, filename=CREDENTIALS_FILE):
    if not os.path.exists(filename):
        print("No credentials file found.")
        return
    
    with open(filename, 'r') as f:
        lines = f.readlines()
        for line in lines:
            parts = line.strip().split('|')
            if len(parts) != 3:
                print(f"Skipping invalid line: {line}")
                continue
            stored_username, salt, enc_password = parts
            if stored_username == username:
                salt = base64.b64decode(salt)
                user_key = create_key_from_passphrase(user_passphrase, salt)
                try:
                    password = decrypt(enc_password, user_key)
                    print(f'Decrypted Password for {username}: {password}')
                    return
                except Exception as e:
                    print("Incorrect passphrase or an error occurred during decryption.")
                    return
        print("Username not found.")

# Main functionality
if __name__ == "__main__":
    while True:
        print("\nPassword Manager")
        print("1. Save credentials")
        print("2. Load credentials")
        print("3. View password")
        print("4. Exit")
        choice = input("Choose an option: ").strip()
        
        if choice == '1':
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            user_passphrase = input("Enter a passphrase to secure this password: ").strip()
            save_credentials(username, password, user_passphrase)
            print("Credentials saved successfully.")
        elif choice == '2':
            load_credentials()
        elif choice == '3':
            username = input("Enter username: ").strip()
            print("Enter your passphrase to view the password:")
            user_passphrase = input("Enter your passphrase: ").strip()
            view_password(username, user_passphrase)
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please try again.")
