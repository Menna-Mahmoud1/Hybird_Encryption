import os
import json #to store encrypted output in JSON format
import base64 #convert binary data into text-friendly encoding (so it can go inside JSON)
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes #generate cryptographically secure random bytes
from Crypto.Protocol.KDF import HKDF       #derive a symmetric AES key from the shared secret
from Crypto.Hash import SHA256             #hash function inside HKDF.
from pqcrypto.kem import ml_kem_512

# ---------- Helpers ----------
def b64(x: bytes) -> str:                 #takes bytes, returns a base64 string.
    return base64.b64encode(x).decode('ascii')

def ub64(s: str) -> bytes:                #takes base64 string, returns the original bytes.
    return base64.b64decode(s.encode('ascii'))

# ---------- KEM Keypair ----------
def generate_kem_keypair(dir_path: str):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
        print(f"[+] Directory created: {dir_path}")

    pub_path = os.path.join(dir_path, "mlkem512_public.key")
    sec_path = os.path.join(dir_path, "mlkem512_secret.key")

    public_key, secret_key = ml_kem_512.generate_keypair()
    with open(pub_path, "wb") as f:
        f.write(public_key)
    with open(sec_path, "wb") as f:
        f.write(secret_key)

    print(f"[+] Public key saved to {pub_path}")
    print(f"[+] Secret key saved to {sec_path}")

# ---------- Encryption ----------
def encrypt_file_with_kem(file_path: str, pub_path: str):

    if not os.path.exists(file_path):
        print("[-] File not found.")
        return
    if not os.path.exists(pub_path):
        print("[-] Public key file not found.")
        return

    with open(pub_path, "rb") as f:
        public_key = f.read()
    with open(file_path, "rb") as f:
        plaintext = f.read()

    kem_ciphertext, shared_secret = ml_kem_512.encrypt(public_key) 
    aes_key = HKDF(shared_secret, 32, salt=None, hashmod=SHA256)

    nonce = get_random_bytes(12)                         # must be unique for every AES key
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce) # cipher object from PyCryptodome library
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    data = {                                        #JSON file
        "alg": "AES-256-GCM+ML-KEM-ml_kem_512",
        "kem_ciphertext": b64(kem_ciphertext),
        "aes_nonce": b64(nonce),
        "aes_tag": b64(tag),
        "ciphertext": b64(ciphertext),
        "original_name": os.path.basename(file_path),
    }

    out_path = file_path + ".pq.json"
    with open(out_path, "w") as f:
        json.dump(data, f)
    print(f"[+] File encrypted and saved to {out_path}")

# ---------- Decryption ----------
def decrypt_file_with_kem(json_path: str, sec_path: str):

    if not os.path.exists(json_path):
        print("[-] Encrypted JSON file not found.")
        return
    if not os.path.exists(sec_path):
        print("[-] Secret key file not found.")
        return

    with open(sec_path, "rb") as f:
        secret_key = f.read()
    with open(json_path, "r") as f:
        data = json.load(f)

    kem_ciphertext = ub64(data["kem_ciphertext"])  #return the original bytes 
    nonce = ub64(data["aes_nonce"])
    tag = ub64(data["aes_tag"])
    ciphertext = ub64(data["ciphertext"])
    original_name = data.get("original_name", "decrypted_file")

    shared_secret = ml_kem_512.decrypt(secret_key, kem_ciphertext)
    aes_key = HKDF(shared_secret, 32, salt=None, hashmod=SHA256)

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    out_path = f"dec_{original_name}"
    with open(out_path, "wb") as f:
        f.write(plaintext)
    print(f"[+] File decrypted and saved to {out_path}")

# ---------- Main Menu ----------
if __name__ == "__main__":
    while True:
        print("\n=== ML-KEM-512 + AES-GCM Hybrid Encryption Tool ===")
        print("1. Generate ML-KEM-512 key pair")
        print("2. Encrypt file")
        print("3. Decrypt file")
        print("4. Exit")
        choice = input("Select option (1-4): ").strip()

        if choice == "1":
            dir_path = input("Enter directory path to save keys: ").strip('"')
            generate_kem_keypair(dir_path)

        elif choice == "2":
            file_path = input("Enter file path to encrypt: ").strip('"')
            pub_path = input("Enter public key path: ").strip('"')
            encrypt_file_with_kem(file_path, pub_path)

        elif choice == "3":
            json_path = input("Enter encrypted JSON file path: ").strip('"')
            sec_path = input("Enter secret key path: ").strip('"')
            decrypt_file_with_kem(json_path, sec_path)

        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option. Try again.")
