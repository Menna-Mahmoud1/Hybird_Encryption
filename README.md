# 🔐 Hybird_Encryption

A **hybrid encryption tool** that combines:  
- 🧩 **ML-KEM (Kyber 512)** — Post-quantum Key Encapsulation Mechanism  
- 🔒 **AES-256-GCM** — Authenticated symmetric encryption  

This tool enables you to:  
1️⃣ Generate Kyber key pairs (public & secret)  
2️⃣ Encrypt files using AES with securely shared keys via Kyber  
3️⃣ Decrypt files using the secret key  

---

## ✨ Features
- 🛡️ Post-quantum secure — protects against quantum attacks  
- 🔑 Strong symmetric encryption (AES-256-GCM with integrity)  
- 📦 Clean JSON output that stores all necessary components  
- 🖥️ Simple interactive menu for ease of use  

---

## 📂 Repository Structure
.

├──Hybird_AES.py  # the tool

└──read.md # this documentation

---

## ⚙️ Installation

1. **Clone the repository**
  
       git clone https://github.com/Menna-Mahmoud1/Hybird_Encryption.git
   
       cd Hybird_Encryption
   
Install dependencies (requires Python 3.8+):

     pip install pycryptodome pqcrypto

📚 Library breakdown:

pycryptodome → AES, random generation

pqcrypto → Kyber 512 (ML-KEM) implementation

🚀 Usage
Run the tool:

python Hybird_AES.py
You’ll get a menu like:

=== ML-KEM-512 + AES-GCM Hybrid Encryption Tool ===
1. Generate ML-KEM-512 key pair
2. Encrypt file
3. Decrypt file
4. Exit
Select option (1-4):
1️⃣ Generate Key Pair
Prompts for a directory to store keys (keys/ by default)

Creates:

-mlkem512_public.key

-mlkem512_secret.key

-Encrypt File
Prompts for:

📂 File path to encrypt

🔑 Public key path

Produces <filename>.pq.json that includes:

🧾 KEM ciphertext

🌀 AES nonce & authentication tag

🔐 AES-encrypted blob

3️⃣ Decrypt File
Prompts for:

📂 Encrypted JSON path

🔑 Secret key path

Outputs decrypted file prefixed with dec_

🛠️ How It Works

🔑 Key Generation

Uses ML-KEM-512 to derive a public/secret key pair.

📤 Encryption

Performs KEM encryption:


    ct, ss = kem.encrypt(public_key)
   ct: ciphertext that hides the shared secret
   
   ss: shared secret used to derive AES key via HKDF

Encrypts file with AES-GCM (with nonce and tag)

Saves everything into .pq.json

📥 Decryption

Uses ct and Kyber secret key to recover ss

Derives AES key

Decrypts & verifies integrity with AES-GCM

🧮 Algorithms Used

-ML-KEM-512 (Kyber) → Post-quantum key encapsulation

-AES-256-GCM → Authenticated symmetric encryption

-HKDF-SHA256 → Derive AES key from KEM’s shared secret

📋 Prerequisites

 Python 3.8+

Install required libraries:

    pip install pycryptodome pqcrypto
   

✨ Built as part of a post-quantum cryptography project to securely combine Kyber + AES for file protection.

📩 If you have questions or feedback, feel free to reach out!
