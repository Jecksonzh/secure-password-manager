# Secure Password Manager

A Python-based password manager with AES encryption, secure key derivation, and bcrypt authentication. Built as a cybersecurity project to demonstrate cryptographic principles and secure storage practices.

![Password Manager Demo](https://via.placeholder.com/600x400?text=Add+Screenshot+Here)

## 🔐 Features

- **User Authentication**: Bcrypt password hashing with unique salt per user
- **AES Encryption**: All stored passwords encrypted using Fernet (AES-128 in CBC mode)
- **Secure Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Password Vault**: Encrypted storage for website credentials
- **Password Sharing**: Securely share encrypted passwords between users
- **Password Generator**: Generate cryptographically strong random passwords
- **Username Generator**: Create random usernames for account creation
- **Account Recovery**: Security questions with encrypted answers
- **GUI Interface**: User-friendly Tkinter-based interface

## 🛠️ Technologies Used

- **Python 3.x**
- **cryptography** library - Fernet symmetric encryption
- **bcrypt** - Password hashing and salt generation
- **PBKDF2-HMAC** - Key derivation function
- **Tkinter** - GUI framework

## 🔒 Security Implementation

### Authentication Layer
✅ Master password hashed with bcrypt (cost factor: 12)  
✅ Unique salt generated per user (16 bytes random)  
✅ Secure password verification without storing plaintext

### Encryption Layer
✅ PBKDF2-HMAC-SHA256 key derivation (100,000 iterations)  
✅ Fernet encryption (AES-128-CBC with HMAC authentication)  
✅ All vault passwords encrypted at rest  
✅ Shared passwords encrypted with recipient's key  
✅ Security answers encrypted with user's key

### Key Management
✅ Encryption keys derived from master password + salt  
✅ Keys stored only in memory during session  
✅ No keys written to disk  
✅ Keys destroyed on logout

## 📦 Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

## 🚀 Usage

### 1. Register a New Account
- Enter a unique username
- Create a strong master password
- Click "Register"

### 2. Login
- Enter your credentials
- Encryption key is automatically derived from your password

### 3. Store Passwords
- Click "Open Vault"
- Add website name and password
- Passwords are encrypted before storage

### 4. Generate Passwords
- Click "Generate Password" for a strong random password
- Default length: 12 characters (uppercase, lowercase, digits, symbols)

### 5. Share Passwords
- Click "Share Password"
- Enter website, password, and recipient username
- You'll need the recipient's password for secure encryption
- Recipient can view shared passwords after login

### 6. Set Security Question
- Click "Set Security Question" for account recovery
- Question and answer are encrypted


### Encryption Flow
1. User registers with master password
2. Random 16-byte salt generated
3. PBKDF2 derives encryption key from password + salt
4. All sensitive data encrypted with Fernet before file storage
5. On login, key regenerated from password + stored salt
6. Data decrypted on-demand in memory only

## 📁 File Structure
```
secure-password-manager/
├── main.py                      # Main application code
├── users.txt                    # Encrypted: usernames, bcrypt hashes, salts
├── vault.txt                    # Encrypted: website credentials
├── shared_passwords.txt         # Encrypted: shared credentials
├── verify_pass.txt              # Encrypted: security Q&A
└── README.md                    # Documentation
```

## ⚠️ Known Limitations

- **File-based storage**: No database with transaction support
- **Password sharing**: Requires knowing recipient's password (asymmetric encryption would be better)
- **No password history**: Cannot track old passwords
- **Single-device**: No cloud sync or multi-device support
- **No 2FA**: Two-factor authentication not implemented
- **Session management**: No auto-lock or timeout features

## 🔮 Future Improvements

- [ ] Migrate to SQLite database with encrypted fields
- [ ] Implement RSA asymmetric encryption for password sharing
- [ ] Add password strength meter and validation
- [ ] Implement two-factor authentication (TOTP)
- [ ] Add session timeout and auto-lock
- [ ] Password history and breach checking (Have I Been Pwned API)
- [ ] Export/import functionality
- [ ] Secure clipboard clearing after copy
- [ ] Master password change with re-encryption
- [ ] Cross-platform support (Windows/Mac/Linux)

## 🎓 Learning Outcomes

This project demonstrates understanding of:
- Symmetric vs asymmetric encryption
- Password hashing vs encryption
- Key derivation functions (KDF)
- Salt generation and usage
- Secure storage practices
- Python cryptography libraries
- GUI development with Tkinter

## ⚖️ License

MIT License - See LICENSE file for details

## 📝 Disclaimer

**This is an educational project.** While it implements genuine cryptographic principles, it has not undergone professional security audit. For production use of sensitive data, please use established password managers like Bitwarden, 1Password, or KeePass.

## 👤 Author

**Jeckson**  
Cybersecurity Student | PSB Academy  
[GitHub](https://github.com/jecksonzh) | [LinkedIn](https://www.linkedin.com/in/jeckson-zhang-24a2a5320)

---

Built as part of my cybersecurity portfolio to demonstrate practical application of cryptographic concepts and secure coding practices.
```
