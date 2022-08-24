import requests
import hashlib
import json
from getpass import getpass
from Crypto.Cipher import AES

API_URL = "http://127.0.0.1:8000/api/"

AUTH_ENDPOINT = "auth"
REGISTER_ENDPOINT = "register"
REQUEST_VAULT_ENDPOINT = "get_vault"
UPDATE_VAULT_ENDPOINT = "update_vault"
UPDATE_KEY_ENDPOINT = "update_key"

PASS_HASH_ITERATIONS = 200200

# ----- API request functions -----

class Result:
    """
    A simple class that stores a simplified result from an API request

    This holds the "success" of an API request, a boolean that represents if it
    succeeded or not, and the "text" or body of the response.
    """
    def __init__(self, success: bool, text: str) -> None:
        self.success = success
        self.text = text

def make_request(endpoint, headers):
    r = requests.get(API_URL + endpoint, headers=headers)

    if r.status_code != 200:
        print(f"Request failed, status code: {r.status_code}")

    return Result(r.status_code == 200, r.text)

def authenticate(auth_key: str):
    """
    Authenticates a user by their authentication key.

    This is a helpful endpoint to just check if the user's login is correct before
    they attempt to request their vault.

    result.text should be "1" for yes and "0" for no
    """
    headers = {
            "x-auth-key": auth_key
    }

    return make_request(AUTH_ENDPOINT, headers)

def register(email: str, auth_key: str, vault: str):
    """
    Registers a new user to the password manager.
    """
    headers = {
        "x-email": email,
        "x-auth-key": auth_key,
        "x-vault": vault
    }

    return make_request(REGISTER_ENDPOINT, headers)

def update_key(old_auth_key: str, new_auth_key: str):
    """
    Updates a user's key to the password manager
    """
    headers = {
            "x-auth-key": old_auth_key,
            "x-new-auth-key": new_auth_key
    }

    return make_request(UPDATE_KEY_ENDPOINT, headers)

def get_vault(auth_key: str):
    """
    Requests the vault from the API

    The vault, if successful, is returned as a hex string of the encrypted bytes
    """
    headers = {
            "x-auth-key": auth_key
    }

    return make_request(REQUEST_VAULT_ENDPOINT, headers)

def update_vault(auth_key: str, new_vault: str):
    """
    Updates a user's vault in the password manager
    """
    headers = {
        "x-auth-key": auth_key,
        "x-vault": new_vault
    }

    return make_request(UPDATE_VAULT_ENDPOINT, headers)

# ----- Key-related functions -----

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

# ----- Vault-related functions -----

class Vault:
    def __init__(self, json_str: str) -> None:
        self._vault = json.loads(json_str)

    @staticmethod
    def new():
        default = {
                "version": "0.1.0",
                "logins": [],
                "notes": []
        }

        default_str = json.dumps(default)

        return Vault(default_str)

    @staticmethod
    def decrypt_from(encrypted_vault, vault_key):
        cipher = AES.new(vault_key, AES.MODE_SIV)
        
        # The tag is stored at the end of the vault
        vault_bytes = encrypted_vault[:-16]
        tag_bytes = encrypted_vault[-16:]

        plaintext = cipher.decrypt_and_verify(vault_bytes, tag_bytes)

        return Vault(plaintext)

    def to_json(self) -> str:
        return json.dumps(self._vault)

    def encrypt(self, vault_key):
        json_str = self.to_json()
        vault_bytes = json_str.encode("utf-8")

        cipher = AES.new(vault_key, AES.MODE_SIV)

        ciphertext, tag = cipher.encrypt_and_digest(vault_bytes)

        # The tag will just be appended to the ciphertext
        return ciphertext + tag

    def add_login(self, login):
        self._vault["logins"].append(login)
    
    def logins(self):
        return self._vault["logins"]

    def remove_login(self, login_index):
        del self._vault["logins"][login_index]

def return_or_request_vault(auth_key, vault_key, vault):
    if vault is not None:
        return vault
    else:
        response = get_vault(auth_key.hex())

        if response.success:
            vault_bytes = bytes.fromhex(response.text)
            
            vault = Vault.decrypt_from(vault_bytes, vault_key)

            return vault
        else:
            print("API access error for /get_vault/")
            
            return None

def return_and_update_vault(auth_key, vault_key, vault):
    print(f"{vault.to_json()}")

    response = update_vault(auth_key.hex(), vault.encrypt(vault_key).hex())

    if response.success:
        return vault
    else:
        print("Failed to update vault")

        return None

def view_vault_action(auth_key, vault_key, vault):
    vault = return_or_request_vault(auth_key, vault_key, vault)

    if vault is not None:
        print(f"{vault.to_json()}")
        print("Logins: ")
        for login in vault.logins():
            print(f"Name: {login['name']}")
            print(f"Websites: {login['websites']}")
            print(f"Username: {login['username']}")
            print(f"Password: {login['password']}")
            if login['description']:
                print(f"Desc: {login['description']}")
    else:
        print("Error requesting vault")

    return vault

def add_login_action(auth_key, vault_key, vault):
    vault = return_or_request_vault(auth_key, vault_key, vault)
    
    if vault is not None:
        print("Please provide the details for the new login:")

        name = input("Name: ")
        websites_str = input("Websites (comma separated): ")
        websites = websites_str.split(",")
        description = input("Description (optional): ")
        username = input("Username: ")
        password = get_confirmed_password()

        login = create_login(websites, name, username, password, description)

        vault.add_login(login)

        vault = return_and_update_vault(auth_key, vault_key, vault)

        if vault is not None:
            print("Successfully added login")
        else:
            print("Failed to add login")

    else:
        print("Error requesting vault")

    return vault

def remove_login_action(auth_key, vault_key, vault):
    vault = return_or_request_vault(auth_key, vault_key, vault)

    if vault is not None:
        print("Displaying list of login names: ")

        for i, login in enumerate(vault.logins()):
            print(f"{i}) Name: {login['name']}, websites: {login['websites']}")

        login_num = int(input("Please provide the number of the login you would like to remove, or an invalid number to cancel: "))

        if login_num in range(len(vault.logins())):

            vault.remove_login(login_num)

            vault = return_and_update_vault(auth_key, vault_key, vault)

            if vault is not None:
                print("Successfully removed login")
            else:
                print("Error removing login")
        else:
            print("Login removal cancelled.")
    else:
        print("Error requesting vault")

    return vault

def update_master_password_action(email, auth_key, vault_key, vault):
    # This is required so that we request our vault and decrypt it using the old key
    # so that we can re-encrypt and update it in the database
    vault = return_or_request_vault(auth_key, vault_key, vault)

    if vault is not None:
        print("Please enter your new password:")
        new_password = get_confirmed_password()

        new_vault_key = generate_vault_key(email, new_password)
        new_auth_key = generate_auth_key(new_vault_key, new_password)

        response = update_key(auth_key.hex(), new_auth_key.hex())

        if response.success:
            # Now we have to update the vault in our database
            response = update_vault(new_auth_key.hex(), vault.encrypt(new_vault_key).hex())

            if response.success:
                print("Successfully updated master password")

                return (new_auth_key, new_vault_key, vault)
            else:
                # This is REALLY bad, because we have now updated our master key, but our vault is still
                # encrypted using the old key. In this situation our best bet is to try to revert the change.
                # Theoretically though, if this frontend was written correctly this would never happen.
                print("THIS WAS PROGRAMMED WRONG, attempting to undo error.")

                response = update_key(new_auth_key.hex(), auth_key.hex())

                if response.success:
                    print("Failed to update master password, but reverted error. Please yell at the developer of this.")
                else:
                    # This is why we really need to look out for this and debug debug debug!!!
                    print("FAILED TO REVERT ERROR. Your account may be unusable.")
        else:
            print("Failed to update master password")
    else:
        print("Error requesting vault, unable to update password")
    
    return (auth_key, vault_key, vault)

def create_login(websites, name, username, password, description):
    login = {
            "websites": websites,
            "name": name,
            "username": username,
            "password": password,
            "description": description
    }

    return login

def get_confirmed_password() -> str:
    password_1 = getpass("Password: ")
    password_2 = getpass("Confirm password: ")

    while password_1 != password_2:
        print("Passwords do not match, please try again:")
        password_1 = getpass("Password: ")
        password_2 = getpass("Confirm password: ")

    return password_1

def main():
    print("Welcome to your password manager!")

    answer = None

    # Keep asking the user for either y or n, loop if their answer is neither
    while answer is None:
        answer = input("Login? y/n > ")

        if answer.lower() == "y":
            answer = True
        elif answer.lower() == "n":
            answer = False
        else:
            answer = None

    # If the user wishes to login
    if answer:
        email = input("Email: ")
        password = getpass("Password: ")

        vault_key = generate_vault_key(email, password)
        auth_key = generate_auth_key(vault_key, password)

        response = authenticate(auth_key.hex())

        if response.success:
            if response.text == "1":
                print("Login successful")

                vault = None

                while True:
                    print("What would you like to do?")

                    actions = ["View vault", "Add login", "Update master password", "Remove login", "Quit"]

                    for i, action in enumerate(actions):
                        print(f"{i}) {action}")

                    chosen_action = int(input("> "))

                    action = None

                    while action is None:
                        if chosen_action in range(len(actions)):
                            action = chosen_action
                        else:
                            print("Invalid choice, please try again:")
                            chosen_action = int(input("> "))

                    if action == 0:
                        vault = view_vault_action(auth_key, vault_key, vault)
                    elif action == 1:
                        vault = add_login_action(auth_key, vault_key, vault)
                    elif action == 2:
                        auth_key, vault_key, vault = update_master_password_action(email, auth_key, vault_key, vault)
                    elif action == 3:
                        vault = remove_login_action(auth_key, vault_key, vault)
                    elif action == 4:
                        print("Goodbye!")
                        break
                    else:
                        print("You programmed it wrong.")
            else:
                print("Incorrect email or password")
        else:
            print("API access error for /auth/")

    # If the user wishes to register for a new account
    else:
        print("Please provide your email and desired password:")

        email = input("Email: ")

        password = get_confirmed_password()

        vault_key = generate_vault_key(email, password)
        auth_key = generate_auth_key(vault_key, password)

        vault = Vault.new()

        encrypted_vault = vault.encrypt(vault_key)

        if register(email, auth_key.hex(), encrypted_vault.hex()).success:
            print("Registration successful")
        else:
            print("Registration failed, please try again")

if __name__ == "__main__":
    main()
