from getpass import getpass
from .my_api import authenticate, register
from .gen_key import generate_auth_key, generate_vault_key
from .vault import Vault
from .actions import view_vault_action, add_login_action, remove_login_action, update_master_password_action, get_confirmed_password

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

                # Allow the user to make however many requests there want with a simple while True
                while True:
                    print("What would you like to do?")

                    actions = ["View vault", "Add login", "Update master password", "Remove login", "Quit"]

                    for i, action in enumerate(actions):
                        print(f"{i}) {action}")

                    # Asks the user for their desired action
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
