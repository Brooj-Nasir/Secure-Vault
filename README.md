# Secure-Vault
# 🔐 File & Folder Encryption Web App

A secure and user-friendly web application that allows users to **upload files or folders**, encrypt them with a **password**, and later **decrypt** them using the same password. Built for privacy, portability, and ease of use.

---

## 🚀 Features

- 🔒 Password-Protected Encryption using AES-256
- 📁 Upload Single or Multiple Files and Folders
- 📥 Download Encrypted Files
- 🔓 Upload Encrypted Files for Decryption
- ❌ Error Handling for Incorrect Passwords or Invalid Files
- 🎨 Clean, responsive UI using HTML/CSS + JavaScript
- 📦 Optional: Folders are zipped before encryption

---

## 🛠️ Technologies Used

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python (Flask) or Node.js (Express)
- **Encryption Library:** `cryptography` (Python) or `crypto` (Node.js)
- **UI Framework:** Bootstrap or Tailwind CSS

---

## 📂 Folder Structure

project-root/
│
├── static/ # Static assets (CSS, JS)
│
├── templates/ # HTML templates (Flask only)
│
├── app.py / index.js # Main backend file (Python or Node.js)
│
├── requirements.txt # For Python dependencies
│
├── README.md # Project documentation
│
└── uploads/ # Temporarily stored uploaded files

yaml
Copy
Edit

---

## 🔧 Installation & Setup

### ▶️ Run on Replit

1. Fork or create project using this code on [Replit](https://replit.com).
2. Replit automatically installs dependencies.
3. Click the **"Run"** button to start the server.
4. Open the web preview in a new tab to use the app.

🧪 Usage Instructions
Upload one or more files or a folder.

Enter a secure password for encryption.

Click "Encrypt" to download the encrypted file.

To decrypt, upload the encrypted file and enter the same password.

The decrypted original file will be available for download if the password is correct.

![image](https://github.com/user-attachments/assets/f6c4e0a7-fc69-441b-8dd6-a4606a50f33c)
![image](https://github.com/user-attachments/assets/0895b8e7-bfec-4ad2-a0f7-8519403fa482)


⚠️ Security Disclaimer
This app does not store any passwords or files permanently.

All encryption/decryption is done on the server or in memory only.

For highly sensitive data, use industry-grade tools and security audits.


📃 License
This project is licensed under the MIT License — free to use, modify, and distribute.

🙋‍♂️ Author
Brooj Nasir
Cybersecurity & Software Enthusiast
Feel free to fork, contribute, or raise issues!






