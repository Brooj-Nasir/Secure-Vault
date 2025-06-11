# Flask Web Application for Secure File Encryption
# This application allows users to encrypt and decrypt files using AES-256 encryption
# with password-based key derivation (PBKDF2)

import os
import logging
import zipfile
import tempfile
import shutil
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from crypto_utils import encrypt_file, decrypt_file, generate_key_from_password

# Configure logging to help with debugging
# This will show detailed information about what the app is doing
logging.basicConfig(level=logging.DEBUG)

# Create Flask application instance
app = Flask(__name__)

# Set secret key for session management and security
# In production, this should be a random, secret value stored in environment variables
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# ProxyFix helps Flask work correctly behind reverse proxies (like on Replit)
# It handles HTTP headers properly for HTTPS and hostname detection
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Application Configuration
# ========================

# Directory where uploaded files are temporarily stored
UPLOAD_FOLDER = 'uploads/temp'

# Maximum file size allowed (100MB)
# This prevents users from uploading extremely large files that could crash the server
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB in bytes

# List of allowed file extensions for security
# Only files with these extensions can be uploaded
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar', '7z'}

# Apply configuration to Flask app
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Create the upload directory if it doesn't exist
# exist_ok=True means it won't raise an error if the directory already exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Utility Functions
# =================

def allowed_file(filename):
    """
    Check if a file extension is allowed for upload
    
    Args:
        filename (str): The name of the file to check
        
    Returns:
        bool: True if file extension is allowed, False otherwise
        
    How it works:
        1. Check if filename contains a dot (.)
        2. Split filename by the last dot to get extension
        3. Convert extension to lowercase for case-insensitive comparison
        4. Check if extension is in our ALLOWED_EXTENSIONS set
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def cleanup_old_files():
    """
    Clean up files older than 1 hour from the upload directory
    
    This function runs automatically to prevent the server from filling up with old files.
    It's called every time someone visits the main page.
    
    Security note: Files are automatically deleted for privacy and storage management
    """
    try:
        # Get current time as timestamp (seconds since 1970)
        current_time = datetime.now().timestamp()
        
        # Loop through all files in the upload directory
        for filename in os.listdir(UPLOAD_FOLDER):
            # Skip the .gitkeep file (it's used to keep the directory in version control)
            if filename == '.gitkeep':
                continue
                
            # Build full path to the file
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            
            # Only process actual files (not directories)
            if os.path.isfile(filepath):
                # Get when the file was last modified
                file_time = os.path.getmtime(filepath)
                
                # If file is older than 1 hour (3600 seconds), delete it
                if current_time - file_time > 3600:  # 1 hour in seconds
                    os.remove(filepath)
                    logging.info(f"Cleaned up old file: {filename}")
                    
    except Exception as e:
        # Log any errors that occur during cleanup, but don't crash the app
        logging.error(f"Error during cleanup: {str(e)}")

# Flask Routes (URL Endpoints)
# ============================

@app.route('/')
def index():
    """
    Main page route - serves the home page
    
    This is what users see when they visit the website.
    It also cleans up old files automatically for housekeeping.
    
    Returns:
        HTML: The main page with upload/decrypt forms
    """
    # Clean up old files every time someone visits the page
    cleanup_old_files()
    
    # Render and return the main HTML template
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_files():
    """
    Handle file upload and encryption
    
    This endpoint receives files and a password from the user,
    then encrypts the files and returns download links.
    
    Expected form data:
        - password: The password to use for encryption
        - files: One or more files to encrypt
        
    Returns:
        JSON: Success/failure status and file information
    """
    try:
        # Get the password from the form data
        password = request.form.get('password')
        
        # Validate that a password was provided
        if not password:
            return jsonify({'success': False, 'error': 'Password is required'})

        # Ensure password meets minimum length requirement
        if len(password) < 8:
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters long'})

        # Check if files were uploaded
        if 'files' not in request.files:
            return jsonify({'success': False, 'error': 'No files selected'})

        # Get list of uploaded files
        files = request.files.getlist('files')
        
        # Validate that files were actually selected
        if not files or all(file.filename == '' for file in files):
            return jsonify({'success': False, 'error': 'No files selected'})

        # List to store information about encrypted files
        encrypted_files = []
        
        # Create a temporary directory for processing files
        # This keeps files organized and makes cleanup easier
        temp_dir = tempfile.mkdtemp(dir=UPLOAD_FOLDER)

        try:
            # Decide how to handle the files based on quantity
            if len(files) > 1:
                # MULTIPLE FILES: Create a zip file first, then encrypt the zip
                # This makes it easier for users to manage multiple encrypted files
                
                # Create a unique filename for the zip file using timestamp
                zip_filename = f"files_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
                zip_path = os.path.join(temp_dir, zip_filename)
                
                # Create the zip file with compression
                with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    # Process each uploaded file
                    for file in files:
                        if file and file.filename:
                            # Security check: ensure file type is allowed
                            if not allowed_file(file.filename):
                                return jsonify({'success': False, 'error': f'File type not allowed: {file.filename}'})
                            
                            # Save file temporarily to add it to the zip
                            temp_file_path = os.path.join(temp_dir, secure_filename(file.filename))
                            file.save(temp_file_path)
                            
                            # Add file to zip with original filename
                            zipf.write(temp_file_path, file.filename)
                            
                            # Clean up temporary file (we only need it in the zip now)
                            os.remove(temp_file_path)

                # Encrypt the entire zip file
                encrypted_path = encrypt_file(zip_path, password)
                
                if encrypted_path:
                    # Store information about the encrypted file
                    encrypted_files.append({
                        'original_name': zip_filename,
                        'encrypted_name': os.path.basename(encrypted_path),
                        'size': os.path.getsize(encrypted_path)
                    })
                    # Clean up the original zip file (we only need the encrypted version)
                    os.remove(zip_path)
                else:
                    return jsonify({'success': False, 'error': 'Encryption failed'})
                    
            else:
                # SINGLE FILE: Encrypt the file directly
                file = files[0]
                
                if file and file.filename:
                    # Security check: ensure file type is allowed
                    if not allowed_file(file.filename):
                        return jsonify({'success': False, 'error': f'File type not allowed: {file.filename}'})
                    
                    # Secure the filename to prevent directory traversal attacks
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(temp_dir, filename)
                    
                    # Save the uploaded file
                    file.save(file_path)

                    # Encrypt the file using our crypto utility
                    encrypted_path = encrypt_file(file_path, password)
                    
                    if encrypted_path:
                        # Store information about the encrypted file
                        encrypted_files.append({
                            'original_name': filename,
                            'encrypted_name': os.path.basename(encrypted_path),
                            'size': os.path.getsize(encrypted_path)
                        })
                        # Clean up the original file (we only need the encrypted version)
                        os.remove(file_path)
                    else:
                        return jsonify({'success': False, 'error': 'Encryption failed'})

            # Return success response with file information
            return jsonify({
                'success': True,
                'message': f'Successfully encrypted {len(encrypted_files)} file(s)',
                'files': encrypted_files
            })

        except Exception as e:
            # If anything goes wrong during file processing, clean up the temp directory
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            # Re-raise the exception to be handled by the outer try-catch
            raise e

    except Exception as e:
        # Log the error for debugging purposes
        logging.error(f"Upload error: {str(e)}")
        # Return error response to the user
        return jsonify({'success': False, 'error': f'Upload failed: {str(e)}'})

@app.route('/download/<filename>')
def download_file(filename):
    """
    Handle file downloads (both encrypted and decrypted files)
    
    This endpoint allows users to download files that have been processed.
    The filename is passed in the URL path.
    
    Args:
        filename (str): Name of the file to download (from URL path)
        
    Returns:
        File: The requested file as a download
        or Redirect: Back to main page if file not found
    """
    try:
        # Security: Clean the filename to prevent directory traversal attacks
        filename = secure_filename(filename)
        
        # Build the full path to the file
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        
        # Check if the file actually exists
        if not os.path.exists(file_path):
            # Show user-friendly error message and redirect back to main page
            flash('File not found or has expired', 'error')
            return redirect(url_for('index'))
        
        # Send the file to the user as a download
        # as_attachment=True forces download instead of showing in browser
        return send_file(file_path, as_attachment=True, download_name=filename)
    
    except Exception as e:
        # Log error for debugging
        logging.error(f"Download error: {str(e)}")
        # Show error message and redirect back to main page
        flash('Download failed', 'error')
        return redirect(url_for('index'))

@app.route('/decrypt', methods=['POST'])
def decrypt_files():
    """
    Handle file decryption
    
    This endpoint receives encrypted files and a password from the user,
    then attempts to decrypt the files and returns download links.
    
    Expected form data:
        - password: The password used during encryption
        - files: One or more encrypted files to decrypt
        
    Returns:
        JSON: Success/failure status and file information
    """
    try:
        # Get the password from the form data
        password = request.form.get('password')
        
        # Validate that a password was provided
        if not password:
            return jsonify({'success': False, 'error': 'Password is required'})

        # Check if encrypted files were uploaded
        if 'files' not in request.files:
            return jsonify({'success': False, 'error': 'No files selected'})

        # Get list of uploaded encrypted files
        files = request.files.getlist('files')
        
        # Validate that files were actually selected
        if not files or all(file.filename == '' for file in files):
            return jsonify({'success': False, 'error': 'No files selected'})

        # List to store information about decrypted files
        decrypted_files = []
        
        # Create a temporary directory for processing files
        temp_dir = tempfile.mkdtemp(dir=UPLOAD_FOLDER)

        try:
            # Process each encrypted file
            for file in files:
                if file and file.filename:
                    # Secure the filename to prevent directory traversal attacks
                    filename = secure_filename(file.filename)
                    encrypted_path = os.path.join(temp_dir, filename)
                    
                    # Save the uploaded encrypted file
                    file.save(encrypted_path)

                    # Attempt to decrypt the file using our crypto utility
                    decrypted_path = decrypt_file(encrypted_path, password)
                    
                    if decrypted_path:
                        # Store information about the decrypted file
                        decrypted_files.append({
                            'original_name': filename,
                            'decrypted_name': os.path.basename(decrypted_path),
                            'size': os.path.getsize(decrypted_path)
                        })
                        # Clean up the encrypted file (we only need the decrypted version)
                        os.remove(encrypted_path)
                    else:
                        # If decryption fails, it's usually due to wrong password
                        return jsonify({'success': False, 'error': 'Decryption failed. Please check your password.'})

            # Return success response with file information
            return jsonify({
                'success': True,
                'message': f'Successfully decrypted {len(decrypted_files)} file(s)',
                'files': decrypted_files
            })

        except Exception as e:
            # If anything goes wrong during file processing, clean up the temp directory
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            # Re-raise the exception to be handled by the outer try-catch
            raise e

    except Exception as e:
        # Log the error for debugging purposes
        logging.error(f"Decrypt error: {str(e)}")
        # Return error response to the user
        return jsonify({'success': False, 'error': f'Decryption failed: {str(e)}'})

# Error Handlers
# ==============
# These functions handle different types of errors that might occur

@app.errorhandler(413)
def too_large(e):
    """
    Handle file upload size limit exceeded error
    
    This is triggered when users try to upload files larger than MAX_CONTENT_LENGTH
    """
    return jsonify({'success': False, 'error': 'File too large. Maximum size is 100MB.'}), 413

@app.errorhandler(404)
def not_found(e):
    """
    Handle page not found errors
    
    Instead of showing an ugly 404 page, redirect users back to the main page
    """
    return render_template('index.html'), 404

@app.errorhandler(500)
def server_error(e):
    """
    Handle internal server errors
    
    Log the error for debugging and show a user-friendly message
    """
    logging.error(f"Server error: {str(e)}")
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

# Application Entry Point
# =======================
# This runs when the script is executed directly (not imported as a module)

if __name__ == '__main__':
    # Start the Flask development server
    # host='0.0.0.0' makes it accessible from outside localhost (needed for Replit)
    # port=5000 is the standard Flask development port
    # debug=True enables automatic reloading and detailed error messages
    app.run(host='0.0.0.0', port=5000, debug=True)
