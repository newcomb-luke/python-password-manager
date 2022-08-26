import hashlib

# Constants
PASS_HASH_ITERATIONS = 200200

def generate_vault_key(email: str, password: str):
    """
    Generates the vault key from the provided email and password by hashing them

    Returns the 256 byte key
    """
    email_bytes = email.encode("utf-8")
    password_bytes = password.encode("utf-8")

    # The vault key consists of the password and email being hashed together
    return hashlib.pbkdf2_hmac("sha256", password_bytes, email_bytes, PASS_HASH_ITERATIONS)

def generate_auth_key(vault_key, password: str):
    """
    Generates the authentication key from the provided vault key and password

    Returns the 256 byte key
    """
    password_bytes = password.encode("utf-8")

    # The authentication key is the vault key hashed again with the password
    return hashlib.pbkdf2_hmac("sha256", vault_key, password_bytes, PASS_HASH_ITERATIONS)
