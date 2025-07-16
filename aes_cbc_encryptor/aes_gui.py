import os
import base64
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
import hmac

# === Crypto Settings ===
BLOCK_SIZE = 16
KEY_LENGTH = 32

def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def derive_keys(password, salt):
    key = PBKDF2(password, salt, dkLen=KEY_LENGTH * 2, count=100_000)
    return key[:KEY_LENGTH], key[KEY_LENGTH:]

def is_strong_password(password):
    return (
        len(password) >= 12 and
        any(c.isupper() for c in password) and
        any(c.islower() for c in password) and
        any(c.isdigit() for c in password)
    )

def secure_delete(file_path):
    if os.path.exists(file_path):
        size = os.path.getsize(file_path)
        with open(file_path, "wb") as f:
            f.write(os.urandom(size))
        os.remove(file_path)

# === Text Encryption ===
def encrypt_text():
    password = password_entry_text.get()
    plaintext = plaintext_box.get("1.0", tk.END).strip()
    if not plaintext or not password:
        messagebox.showerror("Missing Input", "Please enter both plaintext and password.")
        return
    if not is_strong_password(password):
        messagebox.showerror("Weak Password", "Password must be 12+ characters with uppercase, lowercase, and digits.")
        return

    salt = get_random_bytes(16)
    iv = get_random_bytes(BLOCK_SIZE)
    aes_key, hmac_key = derive_keys(password, salt)

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode())
    ciphertext = cipher.encrypt(padded)

    hmac_tag = HMAC.new(hmac_key, salt + iv + ciphertext, digestmod=SHA256).digest()
    final_data = salt + iv + ciphertext + hmac_tag
    encrypted_b64 = base64.b64encode(final_data).decode()

    ciphertext_box.delete("1.0", tk.END)
    ciphertext_box.insert(tk.END, encrypted_b64)

def decrypt_text():
    password = password_entry_text.get()
    encrypted_b64 = ciphertext_box.get("1.0", tk.END).strip()
    if not encrypted_b64 or not password:
        messagebox.showerror("Missing Input", "Please enter both ciphertext and password.")
        return
    try:
        data = base64.b64decode(encrypted_b64)
        salt, iv, mac = data[:16], data[16:32], data[-32:]
        ciphertext = data[32:-32]
        aes_key, hmac_key = derive_keys(password, salt)

        mac_check = HMAC.new(hmac_key, salt + iv + ciphertext, digestmod=SHA256).digest()
        if not hmac.compare_digest(mac, mac_check):
            raise ValueError("HMAC verification failed.")

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext)).decode()
        decrypted_box.delete("1.0", tk.END)
        decrypted_box.insert(tk.END, plaintext)
    except Exception as e:
        messagebox.showerror("Decryption Failed", str(e))

# === File Encryption ===
def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_path_var.set(file_path)

def encrypt_file_gui():
    path = file_path_var.get()
    password = password_entry_file.get()
    if not os.path.isfile(path):
        messagebox.showerror("Invalid file", "Please select a valid file.")
        return
    if not is_strong_password(password):
        messagebox.showerror("Weak Password", "Password must be 12+ characters with uppercase, lowercase, and digits.")
        return

    out_path = path + ".encfile"
    salt = get_random_bytes(16)
    iv = get_random_bytes(BLOCK_SIZE)
    aes_key, hmac_key = derive_keys(password, salt)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    mac = HMAC.new(hmac_key, digestmod=SHA256)

    try:
        with open(path, "rb") as fin, open(out_path, "wb") as fout:
            fout.write(salt + iv)
            mac.update(salt + iv)

            while True:
                chunk = fin.read(1024 * BLOCK_SIZE)
                if not chunk:
                    break
                if len(chunk) < 1024 * BLOCK_SIZE:
                    chunk = pad(chunk)
                encrypted = cipher.encrypt(chunk)
                fout.write(encrypted)
                mac.update(encrypted)
                if len(chunk) < 1024 * BLOCK_SIZE:
                    break

            fout.write(mac.digest())

        if delete_var.get():
            secure_delete(path)
        messagebox.showinfo("Success", f"File encrypted to:\n{out_path}")
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

def decrypt_file_gui():
    path = file_path_var.get()
    password = password_entry_file.get()
    if not os.path.isfile(path):
        messagebox.showerror("Invalid file", "Please select a valid file.")
        return
    out_path = path + ".decfile"
    try:
        with open(path, "rb") as fin, open(out_path, "wb") as fout:
            data = fin.read()
            salt, iv, mac = data[:16], data[16:32], data[-32:]
            ciphertext = data[32:-32]
            aes_key, hmac_key = derive_keys(password, salt)
            mac_check = HMAC.new(hmac_key, salt + iv + ciphertext, SHA256).digest()
            if not hmac.compare_digest(mac, mac_check):
                raise ValueError("HMAC verification failed.")
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext))
            fout.write(plaintext)
        messagebox.showinfo("Success", f"File decrypted to:\n{out_path}")
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

def clear_text_fields():
    plaintext_box.delete("1.0", tk.END)
    ciphertext_box.delete("1.0", tk.END)
    decrypted_box.delete("1.0", tk.END)
    password_entry_text.delete(0, tk.END)

def toggle_password_visibility(entry_widget, var):
    entry_widget.config(show="" if var.get() else "*")

# === GUI ===
root = tk.Tk()
root.title("AES-256 Encryptor")
root.geometry("980x720")
root.configure(bg="#2e2e2e")

style = ttk.Style(root)
style.theme_use("clam")
style.configure(".", background="#2e2e2e", foreground="white", fieldbackground="#3e3e3e", highlightthickness=0)
style.map("TButton", background=[("active", "#555")])
style.configure("TButton", background="#444", foreground="white")

notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=5, pady=5)

# === TEXT TAB ===
text_frame = ttk.Frame(notebook)
notebook.add(text_frame, text="Text Encryptor")

tk.Label(text_frame, text="Password:", bg="#2e2e2e", fg="white").grid(row=0, column=0, sticky="w", padx=10, pady=(20, 5))
password_entry_text = tk.Entry(text_frame, show="*", width=50)
password_entry_text.grid(row=0, column=1, padx=5, pady=(20, 5))
show_text_pass = tk.BooleanVar()
tk.Checkbutton(text_frame, text="Show", variable=show_text_pass, bg="#2e2e2e", fg="white",
               command=lambda: toggle_password_visibility(password_entry_text, show_text_pass)).grid(row=0, column=2, sticky="w")

tk.Label(text_frame, text="Plaintext:", bg="#2e2e2e", fg="white").grid(row=1, column=0, sticky="w", padx=10)
plaintext_box = scrolledtext.ScrolledText(text_frame, width=80, height=10)
plaintext_box.grid(row=2, column=0, columnspan=3, padx=10, pady=5)

tk.Label(text_frame, text="Encrypted (Base64):", bg="#2e2e2e", fg="white").grid(row=3, column=0, sticky="w", padx=10)
ciphertext_box = scrolledtext.ScrolledText(text_frame, width=80, height=10)
ciphertext_box.grid(row=4, column=0, columnspan=3, padx=10, pady=5)

tk.Label(text_frame, text="Decrypted Output:", bg="#2e2e2e", fg="white").grid(row=5, column=0, sticky="w", padx=10)
decrypted_box = scrolledtext.ScrolledText(text_frame, width=80, height=10)
decrypted_box.grid(row=6, column=0, columnspan=3, padx=10, pady=5)

tk.Button(text_frame, text="🔒 Encrypt", command=encrypt_text).grid(row=7, column=0, padx=10, pady=10)
tk.Button(text_frame, text="🔓 Decrypt", command=decrypt_text).grid(row=7, column=1, padx=10, pady=10)
tk.Button(text_frame, text="Clear", command=clear_text_fields).grid(row=7, column=2, padx=10, pady=10)

# === FILE TAB ===
file_frame = ttk.Frame(notebook)
notebook.add(file_frame, text="File Encryptor")

file_path_var = tk.StringVar()
tk.Label(file_frame, text="Select File:", bg="#2e2e2e", fg="white").grid(row=0, column=0, padx=10, pady=10)
tk.Entry(file_frame, textvariable=file_path_var, width=60).grid(row=0, column=1, padx=5, pady=10)
tk.Button(file_frame, text="Browse", command=browse_file).grid(row=0, column=2, padx=5, pady=10)

tk.Label(file_frame, text="Password:", bg="#2e2e2e", fg="white").grid(row=1, column=0, padx=10, pady=10)
password_entry_file = tk.Entry(file_frame, show="*", width=50)
password_entry_file.grid(row=1, column=1, padx=5, pady=10)
show_file_pass = tk.BooleanVar()
tk.Checkbutton(file_frame, text="Show", variable=show_file_pass, bg="#2e2e2e", fg="white",
               command=lambda: toggle_password_visibility(password_entry_file, show_file_pass)).grid(row=1, column=2, sticky="w")

delete_var = tk.BooleanVar()
tk.Checkbutton(file_frame, text="Securely delete original after encryption", variable=delete_var,
               bg="#2e2e2e", fg="white").grid(row=2, column=1, padx=10, pady=5)

tk.Button(file_frame, text="🔒 Encrypt File", command=encrypt_file_gui).grid(row=3, column=1, padx=10, pady=20)
tk.Button(file_frame, text="🔓 Decrypt File", command=decrypt_file_gui).grid(row=3, column=2, padx=10, pady=20)

root.mainloop()
