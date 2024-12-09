from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os
import uuid
from argon2 import PasswordHasher

# Define the hostname and server port
host_name = "localhost"
server_port = 8080

# Database setup
db_file = "totally_not_my_privateKeys.db"
conn = sqlite3.connect(db_file)
cursor = conn.cursor()

# Create keys table if it doesn't exist
cursor.execute("""
CREATE TABLE IF NOT EXISTS keys (
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
""")
# Create users table if it doesn't exist
cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
)
""")
# Create auth_logs table if it doesn't exist
cursor.execute("""
CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
""")
conn.commit()

# AES encryption setup
NOT_MY_KEY = os.environ.get("NOT_MY_KEY")
if not NOT_MY_KEY or len(NOT_MY_KEY) != 32:
    raise ValueError("Environment variable NOT_MY_KEY must be set to a 32-byte key")
AES_KEY = NOT_MY_KEY.encode("utf-8")
IV = b"\x00" * 16  # A fixed IV for simplicity (can be randomized for more security)

def encrypt_data(data):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_data(encrypted_data):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

# Function to serialize key to PEM format, encrypt, and store in the database
def store_key(key, exp_offset):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_pem = encrypt_data(pem)
    exp = int((datetime.datetime.now() + exp_offset).timestamp())
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_pem, exp))
    conn.commit()

# Generate keys with different expiration times
store_key(
    rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    ),
    datetime.timedelta(hours=1)
)
store_key(
    rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    ),
    -datetime.timedelta(hours=1))

# Function to retrieve key based on expiration requirement
def retrieve_key(expired=False):
    now = int(datetime.datetime.now().timestamp())
    if expired:
        cursor.execute("SELECT key FROM keys WHERE exp < ? LIMIT 1", (now,))
    else:
        cursor.execute("SELECT key FROM keys WHERE exp >= ? LIMIT 1", (now,))
    row = cursor.fetchone()
    if row:
        encrypted_pem = row[0]
        pem = decrypt_data(encrypted_pem)
        return serialization.load_pem_private_key(pem, password=None)
    return None

# JWKS helper function
def int_to_base64(value):
    value_hex = format(value, 'x')
    value_hex = '0' + value_hex if len(value_hex) % 2 == 1 else value_hex
    value_bytes = bytes.fromhex(value_hex)
    return base64.urlsafe_b64encode(value_bytes).rstrip(b'=').decode('utf-8')

# Password Hasher
ph = PasswordHasher()

# HTTP server class to handle REST API requests
class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        if parsed_path.path == "/register":
            try:
                user_data = json.loads(post_data)
                username = user_data.get("username")
                email = user_data.get("email")
                if not username:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Username is required")
                    return

                # Generate a secure UUID password
                generated_password = str(uuid.uuid4())
                hashed_password = ph.hash(generated_password)

                # Insert the new user into the database
                cursor.execute(""" 
                INSERT INTO users (username, password_hash, email) 
                VALUES (?, ?, ?)
                """, (username, hashed_password, email))
                conn.commit()

                # Return the generated password to the user
                self.send_response(201)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                response = {"password": generated_password}
                self.wfile.write(bytes(json.dumps(response), "utf-8"))
            except sqlite3.IntegrityError as e:
                self.send_response(409)  # Conflict (e.g., username/email already exists)
                self.end_headers()
                self.wfile.write(b"Username or email already exists")
            except (json.JSONDecodeError, KeyError):
                self.send_response(400)  # Bad Request
                self.end_headers()
                self.wfile.write(b"Invalid JSON payload")
            except Exception as e:
                self.send_response(500)  # Internal Server Error
                self.end_headers()
                self.wfile.write(b"An error occurred")
            return

        if parsed_path.path == "/auth":
            expired = 'expired' in parse_qs(parsed_path.query)
            key = retrieve_key(expired=expired)
            if not key:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"No suitable key found")
                return
            
            # Dummy username for this example (adjust as needed for production)
            username = "username"

            # Retrieve user_id based on username
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            user_row = cursor.fetchone()
            user_id = user_row[0] if user_row else None

            # Log the authentication request
            request_ip = self.client_address[0]
            cursor.execute("""
            INSERT INTO auth_logs (request_ip, user_id) 
            VALUES (?, ?)
            """, (request_ip, user_id))
            conn.commit()

            # Generate JWT
            token_payload = {
                "user": username,
                "exp":
                    (datetime.datetime.now()+datetime.timedelta(hours=1)).timestamp()
                    if not expired
                    else (datetime.datetime.now()-datetime.timedelta(hours=1)).timestamp()
            }
            headers = {"kid": "expiredKID" if expired else "goodKID"}
            encoded_jwt = jwt.encode(
                token_payload, key, algorithm="RS256", headers=headers
            )
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return
        
        self.send_response(405)  # Method Not Allowed
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            # Retrieve all valid (non-expired) keys for JWKS
            now = int(datetime.datetime.now().timestamp())
            cursor.execute("SELECT key FROM keys WHERE exp >= ?", (now,))
            keys = cursor.fetchall()

            # Build JWKS response from retrieved keys
            jwks_keys = []
            for encrypted_key_pem in keys:
                pem = decrypt_data(encrypted_key_pem[0])
                key = serialization.load_pem_private_key(
                    pem,
                    password=None
                )
                numbers = key.private_numbers().public_numbers
                jwks_keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(numbers.n),
                    "e": int_to_base64(numbers.e),
                })

            # Send JWKS response with JSON content type
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps({"keys": jwks_keys}), "utf-8"))
            return
        
        self.send_response(405)
        self.end_headers()

# Start and stop the HTTP server
if __name__ == "__main__":
    web_server = HTTPServer((host_name, server_port), MyServer)
    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        cursor.execute("DELETE FROM keys")
        conn.commit()
        conn.close()
        web_server.server_close()