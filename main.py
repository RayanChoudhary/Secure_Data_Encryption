# main.py
import streamlit as st
import sqlite3
import hashlib
import os
from cryptography.fernet import Fernet

# File to store encryption key
KEY_FILE = "simple_secret.key"

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

# Initialize encryption cipher
cipher = Fernet(load_key())

# Create DB and table if not exist
def init_db():
    conn = sqlite3.connect("secure_data.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS voult (
            label TEXT PRIMARY KEY,
            encrypted_text TEXT,
            passkey TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Hash passkey using SHA256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt text using Fernet
def encrypt(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt text
def decrypt(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Streamlit UI
st.title("🔐 Secure Vault with Streamlit + SQLite")

menu = ["Store Secret", "Retrieve Secret"]
choice = st.sidebar.selectbox("Select an Option", menu)

if choice == "Store Secret":
    st.subheader("🔒 Store a New Secret")
    label = st.text_input("Label (Unique ID)")
    secret = st.text_area("Your Secret")
    passkey = st.text_input("Passkey (used for retrieval)", type="password")

    if st.button("Encrypt and Save"):
        if label and secret and passkey:
            conn = sqlite3.connect("secure_data.db")
            c = conn.cursor()

            encrypted = encrypt(secret)
            hashed_key = hash_passkey(passkey)

            try:
                c.execute("INSERT INTO voult (label, encrypted_text, passkey) VALUES (?, ?, ?)",
                          (label, encrypted, hashed_key))
                conn.commit()
                st.success("✅ Secret saved successfully!")
            except sqlite3.IntegrityError:
                st.error("❌ Label already exists!")
            conn.close()
        else:
            st.warning("⚠️ Please fill in all fields.")

elif choice == "Retrieve Secret":
    st.subheader("🔓 Retrieve Your Secret")
    label = st.text_input("Enter Label")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Decrypt"):
        if label and passkey:
            conn = sqlite3.connect("secure_data.db")
            c = conn.cursor()
            c.execute("SELECT encrypted_text, passkey FROM voult WHERE label = ?", (label,))
            result = c.fetchone()
            conn.close()

            if result:
                encrypted_text, stored_hashed_key = result
                if hash_passkey(passkey) == stored_hashed_key:
                    decrypted = decrypt(encrypted_text)
                    st.success("✅ Secret Decrypted:")
                    st.code(decrypted)
                else:
                    st.error("❌ Incorrect passkey!")
            else:
                st.warning("⚠️ No record found for this label.")
        else:
            st.warning("⚠️ Please enter both Label and Passkey.")
