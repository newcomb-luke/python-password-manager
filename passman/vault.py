import json
from Crypto.Cipher import AES

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

