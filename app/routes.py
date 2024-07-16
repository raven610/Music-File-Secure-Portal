from flask import Blueprint, render_template, request, jsonify, send_file
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
from io import BytesIO

import hashlib


main = Blueprint('main', __name__)

def sanitize_filename(filename):
    # Replace or remove special characters that are not safe in filenames
    safe_chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    sanitized_filename = ''.join(c for c in filename if c in safe_chars)
    
    # Trim and replace spaces with underscores
    sanitized_filename = sanitized_filename.strip().replace(' ', '_')

    return sanitized_filename

def decrypt_file(input_file, key):
    with open(input_file, 'rb') as infile:
        encrypted_data = infile.read()
        iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data

def encrypt_data(data, key):
    iv = os.urandom(16)
    # Create an AES cipher object with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    encrypted_data = b''
    
    while len(data) % 16 != 0:
        data += b'\0'
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()
    
    return encrypted_data

# Function to hash image data with hashlib (SHA-256)
def hash_image(file, algorithm='sha256'):
    # Choose the hash algorithm (default is SHA-256)
    hash_func = getattr(hashlib, algorithm)()
    
    while chunk := file.read(4096):  # Read file in chunks of 4096 bytes
        hash_func.update(chunk)
    
    # Get the hexadecimal digest of the hash
    file_hash = hash_func.hexdigest()
    #print(file_hash)
    return file_hash

# Function to verify image data hash with hashlib (SHA-256)
def verify_hash(image_data, stored_hash):
    computed_hash = hash_image(image_data)
    return computed_hash == stored_hash

@main.route('/')
def home():
    return render_template('index.html', title='Home')

@main.route('/encrypt')
def encrypt():
    return render_template('encrypt.html', title='Encrypt')

@main.route('/upload', methods=['POST'])
def upload():
    uploaded_files = [request.files['file1'],request.files['file2']]
    hashkey = hash_image(uploaded_files[1])
    #print(hashkey)
    encrypted_data = encrypt_data(uploaded_files[0].read(), hashkey.encode('utf-8')[:32])
    with open("Files/"+hashkey+'.bin', 'wb') as outfile:
        outfile.write(encrypted_data)

    return jsonify({'message': hashkey})

@main.route('/download', methods=['POST'])
def download():
    uploaded_files = [request.files['file1'],request.files['file2']]
    hashkey = uploaded_files[0].read().strip()
    #print(hashkey)
    verified = verify_hash(uploaded_files[1],hashkey.decode('utf-8'))
    #print(verified)
    if verified == False:
        return jsonify({'message': 'Biometric Authentication Failed.'})
    else:
        decrypted_data = decrypt_file("Files/"+hashkey.decode('utf-8')+'.bin', hashkey[:32])
        
        return send_file(BytesIO(decrypted_data),mimetype='audio/mpeg',as_attachment=True,download_name='decrypted.mp3')

@main.route('/decrypt')
def decrypt():
    return render_template('decrypt.html', title='Decrypt')

@main.app_errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404
