from config.constants import SECRET_KEY_FILE
import logging
from cryptography.fernet import Fernet
import os
import sys

# Extended version with more error handling
def generate_secret_key():
    # Check if secret key exists before generating
    if not os.path.exists(SECRET_KEY_FILE):
        try:
            key = Fernet.generate_key()
            with open(SECRET_KEY_FILE, 'wb') as f:
                f.write(key)
            logging.info(f"New secret key generated and saved to {SECRET_KEY_FILE}.")
        except Exception as e:
            logging.error(f"Failed to generate secret key: {e}")
    else:
        logging.info(f"Secret key already exists at {SECRET_KEY_FILE}.")

def load_secret_key():
    try:
        with open(SECRET_KEY_FILE, 'rb') as f:
            key = f.read()
        if len(key) != 44:
            raise ValueError("Invalid Fernet key: must be 32 bytes, URL-safe base64-encoded.")
        return key
    except FileNotFoundError:
        logging.error(f"Secret key file not found: {SECRET_KEY_FILE}.")
        raise
    except Exception as e:
        logging.error(f"Failed to load secret key: {e}")
        raise

# Initialize Fernet
generate_secret_key()
try:
    SECRET_KEY = load_secret_key()
except ValueError as e:
    logging.error(f"Error loading secret key: {e}")
    sys.exit(1)

fernet = Fernet(SECRET_KEY)

