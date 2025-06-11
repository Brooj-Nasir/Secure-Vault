# Cryptographic Utilities for Secure File Encryption
# ==================================================
# This module provides functions for encrypting and decrypting files using AES-256 encryption
# with password-based key derivation (PBKDF2) for maximum security.
#
# Security Features:
# - AES-256-CBC encryption (industry standard)
# - PBKDF2 key derivation with 100,000 iterations (OWASP recommended)
# - Random salt and IV generation for each encryption
# - Secure padding using PKCS#7
# - Secure file deletion with multiple overwrites

import os
import hashlib
import tempfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import logging

def generate_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Generate a 256-bit encryption key from a password using PBKDF2
    
    This function converts a user password into a strong encryption key using
    PBKDF2 (Password-Based Key Derivation Function 2), which is designed to be
    slow and computationally expensive to prevent brute force attacks.
    
    Args:
        password (str): The user's password
        salt (bytes): Random salt bytes (16 bytes recommended)
        
    Returns:
        bytes: A 256-bit (32 byte) encryption key
        
    Security Notes:
        - Uses SHA-256 as the hash algorithm
        - 100,000 iterations (OWASP recommended minimum for 2023)
        - Salt prevents rainbow table attacks
        - Same password + salt will always generate the same key
    """
    # Convert password string to bytes (UTF-8 encoding)
    password_bytes = password.encode('utf-8')
    
    # Create PBKDF2 key derivation function with security parameters
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),    # Use SHA-256 hash algorithm
        length=32,                    # Generate 32 bytes (256 bits) for AES-256
        salt=salt,                    # Random salt to prevent rainbow table attacks
        iterations=100000,            # 100,000 iterations (OWASP recommended minimum)
        backend=default_backend()     # Use default cryptographic backend
    )
    
    # Derive and return the encryption key
    return kdf.derive(password_bytes)

def encrypt_file(file_path: str, password: str) -> str | None:
    """
    Encrypt a file using AES-256-CBC encryption with password-based key derivation
    
    This function takes a plaintext file and encrypts it using industry-standard
    AES-256 encryption in CBC (Cipher Block Chaining) mode. The password is
    converted to an encryption key using PBKDF2.
    
    Args:
        file_path (str): Path to the file to encrypt
        password (str): Password to use for encryption
        
    Returns:
        str | None: Path to the encrypted file if successful, None if failed
        
    File Format (encrypted file structure):
        [16 bytes salt][16 bytes IV][encrypted data with PKCS#7 padding]
        
    Security Features:
        - Random salt (prevents rainbow table attacks)
        - Random IV (ensures same file encrypts differently each time)
        - PKCS#7 padding (ensures data fits AES block size)
        - AES-256-CBC encryption (industry standard)
    """
    try:
        # Generate cryptographically secure random values
        salt = os.urandom(16)  # 128-bit salt for PBKDF2
        iv = os.urandom(16)    # 128-bit Initialization Vector for AES-CBC
        
        # Derive encryption key from password using PBKDF2
        key = generate_key_from_password(password, salt)
        
        # Create AES cipher in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Read the entire file into memory
        # Note: For very large files, you might want to process in chunks
        with open(file_path, 'rb') as infile:
            plaintext = infile.read()
        
        # Apply PKCS#7 padding to make data a multiple of AES block size (16 bytes)
        # This is required because CBC mode needs complete blocks
        padding_length = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + bytes([padding_length]) * padding_length
        
        # Encrypt the padded data
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        # Create filename for encrypted file
        base_name = os.path.basename(file_path)
        encrypted_filename = f"{base_name}.encrypted"
        encrypted_path = os.path.join(os.path.dirname(file_path), encrypted_filename)
        
        # Write encrypted file with salt + IV + ciphertext format
        # This format allows decryption without knowing salt/IV beforehand
        with open(encrypted_path, 'wb') as outfile:
            outfile.write(salt)        # First 16 bytes: salt for key derivation
            outfile.write(iv)          # Next 16 bytes: IV for decryption
            outfile.write(ciphertext)  # Remaining bytes: encrypted data
        
        logging.info(f"File encrypted successfully: {encrypted_path}")
        return encrypted_path
        
    except Exception as e:
        # Log error details for debugging
        logging.error(f"Encryption error: {str(e)}")
        return None

def decrypt_file(encrypted_file_path: str, password: str) -> str | None:
    """
    Decrypt a file that was encrypted using the encrypt_file function
    
    This function reverses the encryption process by:
    1. Reading the encrypted file and extracting salt, IV, and ciphertext
    2. Deriving the same encryption key using the password and extracted salt
    3. Decrypting the ciphertext using AES-256-CBC
    4. Removing PKCS#7 padding to recover the original data
    
    Args:
        encrypted_file_path (str): Path to the encrypted file
        password (str): Password that was used for encryption
        
    Returns:
        str | None: Path to the decrypted file if successful, None if failed
        
    Common failure reasons:
        - Wrong password (most common)
        - Corrupted encrypted file
        - File not encrypted with this system
        - Invalid padding (indicates wrong password or corruption)
    """
    try:
        # Read the entire encrypted file
        with open(encrypted_file_path, 'rb') as infile:
            encrypted_data = infile.read()
        
        # Validate minimum file size (salt + IV = 32 bytes minimum)
        if len(encrypted_data) < 32:  # 16 bytes salt + 16 bytes IV
            logging.error("Encrypted file is too small")
            return None
            
        # Extract components from encrypted file structure
        salt = encrypted_data[:16]        # First 16 bytes: salt
        iv = encrypted_data[16:32]        # Next 16 bytes: IV
        ciphertext = encrypted_data[32:]  # Remaining bytes: encrypted data
        
        # Derive the same encryption key using password and extracted salt
        key = generate_key_from_password(password, salt)
        
        # Create AES cipher for decryption using extracted IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the ciphertext
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS#7 padding
        # The last byte tells us how many padding bytes were added
        padding_length = padded_plaintext[-1]
        
        # Validate padding length (must be 1-16 for AES)
        if padding_length < 1 or padding_length > 16:
            logging.error("Invalid padding")
            return None
            
        # Verify padding bytes are correct (security check)
        # All padding bytes should have the same value as padding_length
        for i in range(padding_length):
            if padded_plaintext[-(i+1)] != padding_length:
                logging.error("Invalid padding bytes")
                return None
        
        # Remove padding to get original plaintext
        plaintext = padded_plaintext[:-padding_length]
        
        # Generate output filename
        base_name = os.path.basename(encrypted_file_path)
        if base_name.endswith('.encrypted'):
            # Remove '.encrypted' suffix to restore original filename
            decrypted_filename = base_name[:-10]  # Remove '.encrypted' (10 chars)
        else:
            # If filename doesn't end with .encrypted, add .decrypted suffix
            decrypted_filename = f"{base_name}.decrypted"
            
        decrypted_path = os.path.join(os.path.dirname(encrypted_file_path), decrypted_filename)
        
        # Write the decrypted data to file
        with open(decrypted_path, 'wb') as outfile:
            outfile.write(plaintext)
        
        logging.info(f"File decrypted successfully: {decrypted_path}")
        return decrypted_path
        
    except Exception as e:
        # Log error details for debugging
        logging.error(f"Decryption error: {str(e)}")
        return None

def secure_delete(file_path: str) -> bool:
    """
    Securely delete a file by overwriting it with random data multiple times
    
    This function provides defense against data recovery tools by overwriting
    the file contents with random data before deletion. While modern SSDs with
    wear leveling may not be fully protected by this method, it still provides
    reasonable protection against casual data recovery attempts.
    
    Args:
        file_path (str): Path to the file to securely delete
        
    Returns:
        bool: True if file was successfully deleted, False if an error occurred
        
    Security Notes:
        - Uses 3 passes of random data overwriting
        - Flushes data to disk after each pass
        - Finally removes the file from filesystem
        - Returns True if file doesn't exist (already deleted)
        
    Limitations:
        - May not be effective on SSDs with wear leveling
        - May not protect against advanced forensic techniques
        - For maximum security, use full disk encryption
    """
    try:
        # If file doesn't exist, consider it successfully "deleted"
        if not os.path.exists(file_path):
            return True
            
        # Get the size of the file to know how much random data to write
        file_size = os.path.getsize(file_path)
        
        # Overwrite file contents with random data (3 passes)
        # Multiple passes help ensure data is thoroughly overwritten
        with open(file_path, 'r+b') as file:
            for pass_number in range(3):
                # Move to beginning of file for each pass
                file.seek(0)
                
                # Write random data over the entire file
                file.write(os.urandom(file_size))
                
                # Force the operating system to write data to disk immediately
                file.flush()        # Flush Python's buffer
                os.fsync(file.fileno())  # Force OS to write to disk
        
        # Finally delete the file from the filesystem
        os.remove(file_path)
        
        logging.info(f"File securely deleted: {file_path}")
        return True
        
    except Exception as e:
        # Log error details for debugging
        logging.error(f"Secure delete error: {str(e)}")
        return False
