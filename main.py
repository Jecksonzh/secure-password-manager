import tkinter as tk
from tkinter import messagebox, simpledialog
import bcrypt
import random
import string
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# File to store usernames and hashed passwords
USER_DATA_FILE = "users.txt"
VAULT_DATA_FILE = "vault.txt"
SHARED_PASSWORD_FILE = "shared_passwords.txt"
VERIFY_PASS_FILE = "verify_pass.txt"

# Global variable to store encryption key
encryption_key = None
current_user = None

# Generate encryption key from master password
def generate_key_from_password(password, salt):
    """Derive encryption key from master password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Encrypt data
def encrypt_data(data, key):
    """Encrypt data using Fernet symmetric encryption"""
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_data, key):
    """Decrypt data using Fernet symmetric encryption"""
    try:
        f = Fernet(key)
        return f.decrypt(encrypted_data.encode()).decode()
    except:
        return None

# Load users from the file
def load_users():
    users = {}
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "r") as f:
            for line in f:
                data = line.strip().split(',')
                if len(data) == 3:  # username, hashed_password, salt
                    username, hashed_password, salt_b64 = data
                    users[username] = {
                        'password': hashed_password.encode('utf-8'),
                        'salt': base64.b64decode(salt_b64)  # Decode base64 back to bytes
                    }
    return users

# Save user to the file
def save_user(username, hashed_password, salt):
    # Encode salt as base64 for safe storage
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    with open(USER_DATA_FILE, "a") as f:
        f.write(f"{username},{hashed_password.decode('utf-8')},{salt_b64}\n")

# Load verification questions and answers (encrypted)
def load_verification_data():
    verification_data = {}
    if os.path.exists(VERIFY_PASS_FILE):
        with open(VERIFY_PASS_FILE, "r") as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) == 3:
                    username, encrypted_question, encrypted_answer = parts
                    verification_data[username] = (encrypted_question, encrypted_answer)
    return verification_data

# Save verification data (encrypted)
def save_verification_data(username, question, answer):
    global encryption_key
    encrypted_question = encrypt_data(question, encryption_key)
    encrypted_answer = encrypt_data(answer, encryption_key)
    with open(VERIFY_PASS_FILE, "a") as f:
        f.write(f"{username},{encrypted_question},{encrypted_answer}\n")

# Dummy storage for usernames and hashed passwords
users = load_users()
verification_data = load_verification_data()

# Function to hash the password using bcrypt
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Function to verify password
def verify_password(stored_password, entered_password):
    return bcrypt.checkpw(entered_password.encode('utf-8'), stored_password)

# Function to handle login
def login():
    global current_user, encryption_key
    username = username_entry.get()
    password = password_entry.get()

    if username in users and verify_password(users[username]['password'], password):
        current_user = username
        # Generate encryption key from password
        encryption_key = generate_key_from_password(password, users[username]['salt'])
        messagebox.showinfo("Login", "Login Successful!")
        main_page()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")

# Function to handle registration
def register():
    username = username_entry.get()
    password = password_entry.get()

    if username in users:
        messagebox.showerror("Registration Failed", "User already exists")
    else:
        # Generate salt for this user
        salt = os.urandom(16)
        hashed_password = hash_password(password)
        users[username] = {
            'password': hashed_password,
            'salt': salt
        }
        save_user(username, hashed_password, salt)
        messagebox.showinfo("Registration", "Registration Successful!")

# Vault page where passwords can be stored
def open_vault():
    vault_window = tk.Toplevel(window)
    vault_window.title("Create vault")
    vault_window.geometry("400x300")
    vault_window.config(bg="#f0f0f0")

    # Website Label and Entry
    tk.Label(vault_window, text="Website:", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
    website_entry = tk.Entry(vault_window, font=("Arial", 12), width=30)
    website_entry.pack(pady=5)

    # Password Label and Entry
    tk.Label(vault_window, text="Password:", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
    password_entry_vault = tk.Entry(vault_window, font=("Arial", 12), width=30, show="*")
    password_entry_vault.pack(pady=5)

    # Save Button
    tk.Button(vault_window, text="Save Password", font=("Arial", 12), bg="#57a0ff", 
              command=lambda: save_password_vault(website_entry.get(), password_entry_vault.get())).pack(pady=10)

    # View Previous Passwords Button
    tk.Button(vault_window, text="View Saved Passwords", font=("Arial", 12), bg="#57a0ff", 
              command=view_vault).pack(pady=10)

# Function to save the website and password to the vault file (ENCRYPTED)
def save_password_vault(website, password):
    global encryption_key, current_user
    if website and password:
        encrypted_website = encrypt_data(website, encryption_key)
        encrypted_password = encrypt_data(password, encryption_key)
        with open(VAULT_DATA_FILE, "a") as f:
            f.write(f"{encrypted_website},{encrypted_password},{current_user}\n")
        messagebox.showinfo("Saved", "Password saved successfully!")
    else:
        messagebox.showerror("Error", "Please fill both fields!")

# Function to view saved passwords from vault.txt (DECRYPTED)
def view_vault():
    global encryption_key, current_user
    vault_window = tk.Toplevel(window)
    vault_window.title("Saved Vault")
    vault_window.geometry("400x300")
    vault_window.config(bg="#f0f0f0")

    if os.path.exists(VAULT_DATA_FILE):
        with open(VAULT_DATA_FILE, "r") as f:
            data = f.readlines()

        if data:
            found_passwords = False
            for entry in data:
                parts = entry.strip().split(',')
                if len(parts) == 3:
                    encrypted_website, encrypted_password, owner = parts
                    if owner == current_user:
                        website = decrypt_data(encrypted_website, encryption_key)
                        password = decrypt_data(encrypted_password, encryption_key)
                        if website and password:
                            password_label = tk.Label(vault_window, 
                                text=f"Website: {website}, Password: {password}", 
                                font=("Arial", 12), bg="#f0f0f0")
                            password_label.pack(pady=5)
                            found_passwords = True
            if not found_passwords:
                tk.Label(vault_window, text="No passwords saved yet.", 
                        font=("Arial", 12), bg="#f0f0f0").pack(pady=20)
        else:
            tk.Label(vault_window, text="No passwords saved yet.", 
                    font=("Arial", 12), bg="#f0f0f0").pack(pady=20)
    else:
        tk.Label(vault_window, text="No passwords saved yet.", 
                font=("Arial", 12), bg="#f0f0f0").pack(pady=20)

# Function to open password sharing tab
def open_password_sharing():
    share_window = tk.Toplevel(window)
    share_window.title("Password Sharing")
    share_window.geometry("400x400")
    share_window.config(bg="#f0f0f0")

    # Input fields for sharing passwords
    tk.Label(share_window, text="Website:", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
    website_entry = tk.Entry(share_window, font=("Arial", 12), width=30)
    website_entry.pack(pady=5)

    tk.Label(share_window, text="Password:", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
    password_entry = tk.Entry(share_window, font=("Arial", 12), width=30, show="*")
    password_entry.pack(pady=5)

    tk.Label(share_window, text="Recipient (Username):", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
    recipient_entry = tk.Entry(share_window, font=("Arial", 12), width=30)
    recipient_entry.pack(pady=5)

    # Button to share the password
    tk.Button(share_window, text="Share Password", font=("Arial", 12), bg="#57a0ff", 
              command=lambda: share_password(website_entry.get(), password_entry.get(), recipient_entry.get())).pack(pady=10)

    # View shared passwords
    tk.Button(share_window, text="View Shared Passwords", font=("Arial", 12), bg="#57a0ff", 
              command=view_shared_passwords).pack(pady=10)

# Function to share the password with another user (ENCRYPTED)
def share_password(website, password, recipient):
    global encryption_key, current_user
    if website and password and recipient:
        if recipient in users:
            # Get recipient's password to generate their encryption key
            recipient_password = tk.simpledialog.askstring("Recipient Verification", 
                f"Enter {recipient}'s password to share securely:", show='*')
            
            if recipient_password:
                # Generate recipient's encryption key
                recipient_key = generate_key_from_password(recipient_password, users[recipient]['salt'])
                
                # Encrypt with recipient's key so they can decrypt it
                encrypted_website = encrypt_data(website, recipient_key)
                encrypted_password = encrypt_data(password, recipient_key)
                
                with open(SHARED_PASSWORD_FILE, "a") as f:
                    f.write(f"{encrypted_website},{encrypted_password},{current_user},{recipient}\n")
                messagebox.showinfo("Shared", "Password shared successfully!")
            else:
                messagebox.showerror("Error", "Recipient password required for secure sharing.")
        else:
            messagebox.showerror("Error", "Recipient does not exist.")
    else:
        messagebox.showerror("Error", "Please fill all fields!")

# Function to view shared passwords (DECRYPTED)
def view_shared_passwords():
    global encryption_key, current_user
    shared_window = tk.Toplevel(window)
    shared_window.title("View Shared Passwords")
    shared_window.geometry("400x300")
    shared_window.config(bg="#f0f0f0")

    if os.path.exists(SHARED_PASSWORD_FILE):
        with open(SHARED_PASSWORD_FILE, "r") as f:
            data = f.readlines()

        if data:
            found_shared = False
            for entry in data:
                parts = entry.strip().split(',')
                if len(parts) == 4:
                    encrypted_website, encrypted_password, sender, recipient = parts
                    # Display passwords shared with the current user
                    if recipient == current_user:
                        website = decrypt_data(encrypted_website, encryption_key)
                        password = decrypt_data(encrypted_password, encryption_key)
                        if website and password:
                            password_label = tk.Label(shared_window, 
                                text=f"Website: {website}, Password: {password}, Shared by: {sender}", 
                                font=("Arial", 12), bg="#f0f0f0")
                            password_label.pack(pady=5)
                            found_shared = True
            if not found_shared:
                tk.Label(shared_window, text="No shared passwords.", 
                        font=("Arial", 12), bg="#f0f0f0").pack(pady=20)
        else:
            tk.Label(shared_window, text="No shared passwords.", 
                    font=("Arial", 12), bg="#f0f0f0").pack(pady=20)
    else:
        tk.Label(shared_window, text="No shared passwords.", 
                font=("Arial", 12), bg="#f0f0f0").pack(pady=20)

# Generate random password
def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# Function to generate a username
def generate_username():
    username = "user" + str(random.randint(1000, 9999))
    messagebox.showinfo("Generated Username", f"Username: {username}")

# Forgot password feature: Verify question and reset password
def forgot_password():
    global encryption_key
    username = username_entry.get()

    if username in verification_data:
        # Need to temporarily get user's password to decrypt question
        temp_password = tk.simpledialog.askstring("Temporary Password", 
            "Enter any password to view security question (for demo purposes):", show='*')
        
        if temp_password and username in users:
            temp_key = generate_key_from_password(temp_password, users[username]['salt'])
            encrypted_question, encrypted_answer = verification_data[username]
            
            question = decrypt_data(encrypted_question, temp_key)
            correct_answer_encrypted = encrypted_answer
            
            if question:
                answer = tk.simpledialog.askstring("Security Question", question)
                decrypted_correct = decrypt_data(correct_answer_encrypted, temp_key)
                
                if answer and decrypted_correct and answer == decrypted_correct:
                    new_password = tk.simpledialog.askstring("Reset Password", 
                        "Enter new password:", show='*')
                    if new_password:
                        hashed_password = hash_password(new_password)
                        users[username]['password'] = hashed_password
                        # Note: In production, you'd need to re-encrypt all data with new key
                        messagebox.showinfo("Password Reset", 
                            "Password reset successfully! Note: You may need to re-enter stored passwords.")
                else:
                    messagebox.showerror("Error", "Incorrect answer to security question.")
    else:
        messagebox.showerror("Error", "No security question set for this user.")

# Set security question after login
def set_security_question():
    question = tk.simpledialog.askstring("Set Security Question", "Enter a security question:")
    answer = tk.simpledialog.askstring("Set Security Answer", "Enter the answer to your security question:")

    if question and answer:
        save_verification_data(current_user, question, answer)
        verification_data[current_user] = (question, answer)
        messagebox.showinfo("Success", "Security question set successfully!")
    else:
        messagebox.showerror("Error", "Both question and answer are required.")

# Main page after login
def main_page():
    login_frame.pack_forget()  # Hide the login page

    tools_frame = tk.Frame(window, bg="#d3d3d3")
    tools_frame.pack(pady=20)

    welcome_message = f"Welcome, {current_user}"
    tk.Label(tools_frame, text=welcome_message, font=("Arial", 16, "bold"), bg="#d3d3d3").pack(pady=10)
    tk.Label(tools_frame, text="Welcome to the Password Manager!", font=("Arial", 16), bg="#d3d3d3").pack(pady=10)

    tk.Button(tools_frame, text="Open Vault", command=open_vault, font=("Arial", 12), bg="#ffdd57").pack(pady=5)
    tk.Button(tools_frame, text="Generate Password", 
              command=lambda: messagebox.showinfo("Generated Password", generate_password()), 
              font=("Arial", 12), bg="#ffdd57").pack(pady=5)
    tk.Button(tools_frame, text="Generate Username", command=generate_username, 
              font=("Arial", 12), bg="#ffdd57").pack(pady=5)
    tk.Button(tools_frame, text="Share Password", command=open_password_sharing, 
              font=("Arial", 12), bg="#ffdd57").pack(pady=5)
    tk.Button(tools_frame, text="Set Security Question", command=set_security_question, 
              font=("Arial", 12), bg="#ffdd57").pack(pady=5)

# Tkinter window setup with design
window = tk.Tk()
window.title("Secure Password Manager")
window.geometry("400x400")
window.config(bg="#d3d3d3")

# Login/Register Frame
login_frame = tk.Frame(window, bg="#d3d3d3")
login_frame.pack(pady=50)

tk.Label(login_frame, text="Username", font=("Arial", 12), bg="#d3d3d3").pack(pady=5)
username_entry = tk.Entry(login_frame, font=("Arial", 12), width=30)
username_entry.pack(pady=5)

tk.Label(login_frame, text="Password", font=("Arial", 12), bg="#d3d3d3").pack(pady=5)
password_entry = tk.Entry(login_frame, show='*', font=("Arial", 12), width=30)
password_entry.pack(pady=5)

tk.Button(login_frame, text="Login", command=login, font=("Arial", 12), bg="#57a0ff").pack(pady=10)
tk.Button(login_frame, text="Register", command=register, font=("Arial", 12), bg="#57a0ff").pack(pady=10)
tk.Button(login_frame, text="Forgot Password?", command=forgot_password, 
          font=("Arial", 10), bg="#57a0ff").pack(pady=10)

window.mainloop()