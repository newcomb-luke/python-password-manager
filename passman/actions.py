from .my_api import get_vault, update_vault, update_key
from .vault import Vault
from .gen_key import generate_vault_key, generate_auth_key
from getpass import getpass

def view_vault_action(auth_key, vault_key, vault):
    """
    Display's the user's Vault in a human-friendly way
    """
    vault = return_or_request_vault(auth_key, vault_key, vault)

    if vault is not None:
        print("Logins: ")
        for login in vault.logins():
            print(f"Name: {login['name']}")
            print(f"\tWebsites: {login['websites']}")
            print(f"\tUsername: {login['username']}")
            print(f"\tPassword: {login['password']}")
            if login['description']:
                print(f"\tDesc: {login['description']}")
    else:
        print("Error requesting vault")

    return vault

def add_login_action(auth_key, vault_key, vault):
    """
    Adds a new login to the user's Vault
    """
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
    """
    Action to possibly remove a login from a user's Vault
    """
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
    """
    Action to update the user's master password, and therefore vault and authentication keys
    """
    # This is required so that we request our vault and decrypt it using the old key
    # so that we can re-encrypt and update it in the database
    vault = return_or_request_vault(auth_key, vault_key, vault)

    if vault is not None:
        print("Please enter your new password:")
        new_password = get_confirmed_password()

        new_vault_key = generate_vault_key(email, new_password)
        new_auth_key = generate_auth_key(new_vault_key, new_password)

        new_vault = vault.encrypt(new_vault_key)

        response = update_key(auth_key.hex(), new_auth_key.hex(), new_vault.hex())

        if response.success:
            print("Successfully updated master password")

            return (new_auth_key, new_vault_key, vault)
        else:
            print("Failed to update master password")
    else:
        print("Error requesting vault, unable to update password")
    
    return (auth_key, vault_key, vault)

# Utility functions

def return_or_request_vault(auth_key, vault_key, vault):
    """
    Returns the provided Vault if it is not None, or else attempts to request the Vault and return it

    Used as a repeatable way to get the user's Vault
    """
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
    """
    Updates the vault in the databasse using the Vault provided, and returns the Vault on success. On failure,
    returns None so that the Vault can be re-requested
    """
    response = update_vault(auth_key.hex(), vault.encrypt(vault_key).hex())

    if response.success:
        return vault
    else:
        print("Failed to update vault")

        return None

def create_login(websites, name, username, password, description):
    """
    Helpful function to create a new login dictionary from a list of arguments
    """
    login = {
            "websites": websites,
            "name": name,
            "username": username,
            "password": password,
            "description": description
    }

    return login

def get_confirmed_password() -> str:
    """
    Asks the user for a password, and confirms the password to make sure that the user has
    typed their desired password correctly.
    """
    password_1 = getpass("Password: ")
    password_2 = getpass("Confirm password: ")

    while password_1 != password_2:
        print("Passwords do not match, please try again:")
        password_1 = getpass("Password: ")
        password_2 = getpass("Confirm password: ")

    return password_1
