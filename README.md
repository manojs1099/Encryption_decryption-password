# Password Manager

This is a simple password manager implemented in Python. It allows users to save, load, and view their passwords securely.

## Prerequisites

Before running the code, make sure you have the following installed:

- Python 3.x
- Install pip version
- Install pycyptodome from pip - (pip install pycryptodome)

## Getting Started

1. Clone the repository:

   ```shell
   git clone https://github.com/your-username/password-manager.git
Change into the project directory:

shell
Copy code
cd password-manager
Run the password manager:

shell
Copy code
python encryption-decryption_python.py


# Usage

The password manager provides the following options:

- Save credentials: Enter a username and password to save them securely.
- Load credentials: View the saved credentials.
- View password: Enter a username and passphrase to view the decrypted password.
- Exit: Quit the password manager.

# How it Works

The password manager uses the AES symmetric encryption algorithm from the pycryptodome library to encrypt and decrypt passwords. Here's a high-level overview of how the code works:

- Saving credentials: The user's passphrase is used to generate a key using the PBKDF2 key derivation function. The password is then encrypted using the generated key and saved to a file along with the username and a randomly generated salt.
- Loading credentials: The saved credentials are read from the file and displayed to the user.
- Viewing a password: The user's passphrase is used to generate a key, which is then used to decrypt the encrypted password associated with the entered username.

# Security Considerations

- The user's passphrase is used to generate a key for encryption and decryption. It is important to choose a strong and unique passphrase to ensure the security of the saved passwords.
- The salt is randomly generated for each saved credential, adding an extra layer of security by making it more difficult for attackers to use precomputed tables (rainbow tables) to crack the passwords.
- The encrypted passwords are saved to a file, so it is important to secure the file and restrict access to it.

# Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

# License

This project is licensed under the MIT License.
