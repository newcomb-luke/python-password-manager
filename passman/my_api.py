import requests

# Constants
API_URL = "http://127.0.0.1:8000/api/"

AUTH_ENDPOINT = "auth"
REGISTER_ENDPOINT = "register"
REQUEST_VAULT_ENDPOINT = "get_vault"
UPDATE_VAULT_ENDPOINT = "update_vault"
UPDATE_KEY_ENDPOINT = "update_key"

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
