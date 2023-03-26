import json
from cryptography.fernet import Fernet
import getpass
import os

def add_password(service, username, password, key):
    # Encrypt the password using the Fernet key
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())

    # Load the existing data from the JSON file, if any
    try:
        with open('passwords.json', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}

    # Add the new password to the data
    if service in data:
        data[service][username] = encrypted_password.decode()
    else:
        data[service] = {username: encrypted_password.decode()}

    # Save the updated data to the JSON file
    with open('passwords.json', 'w') as f:
        json.dump(data, f)

    print("Password added successfully.")

def get_password(service, username, key):
    # Load the existing data from the JSON file
    try:
        with open('passwords.json', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        return None

    # Decrypt and return the password, if any
    if service in data and username in data[service]:
        encrypted_password = data[service][username].encode()
        f = Fernet(key)
        decrypted_password = f.decrypt(encrypted_password)
        return decrypted_password.decode()
    else:
        return None

def show_passwords():
    # Load the existing data from the JSON file
    try:
        with open('passwords.json', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print("No passwords found.")
        return

    if not data:
        print("No passwords found.")
        return

    # Print the stored passwords
    for service in data:
        print(service + ":")
        for username, encrypted_password in data[service].items():
            f = Fernet(key)
            decrypted_password = f.decrypt(encrypted_password.encode()).decode()
            print(f" username: {username}\n password: {decrypted_password}\n")
        print()

def delete_password(service, username, key):
    # Load the passwords from the file
    with open('passwords.json', 'r') as f:
        passwords = json.load(f)

    # Check if the service and username are in the passwords dictionary
    if service in passwords and username in passwords[service]:
        # Remove the password from the dictionary
        del passwords[service][username]

        # Check if the service is now empty
        if not passwords[service]:
            del passwords[service]

        # Update the passwords file
        with open('passwords.json', 'w') as f:
            json.dump(passwords, f)

        print("Password deleted for", service, "and", username)
    else:
        print("No password found for", service, "and", username)

def create_master_key():
    key_path = os.path.join(os.getcwd(), "master.key")
    if not os.path.isfile(key_path):
        password = getpass.getpass(prompt='Enter a password for your master key: ')

        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        ciphered_text = cipher_suite.encrypt(password.encode())

        with open(key_path, "wb") as f:
            f.write(key)
        print("Master key created successfully!")
    else:
        print("Master key already exists, skipping creation")
    
# Main program

passphrase="root"
user_passphrase_input=input("Please enter your passphrase.\n") # This will change in future.

if user_passphrase_input==passphrase:

    create_master_key()
    key = open("master.key", "rb").read()  # Read the master key from the file
    while True:
        userchoice = input("Will you add, get, or show your passwords?\n1:add\n2:get\n3:show\n4:delete\n5:exit\n")

        if userchoice == '1':
            service = input("Enter the service name: ")
            username = input("Enter your username: ")
            password = input("Enter your password: ")

            add_password(service, username, password, key)
        elif userchoice == '2':
            service = input("Enter the service name: ")
            username = input("Enter your username: ")

            password = get_password(service, username, key)

            if password:
                print("Your password for", service, "is", password)
            else:
                print("No password found for", service, "and", username)
        elif userchoice == '3':
            show_passwords()
        elif userchoice == "4":
            # Code for deleting password
            service = input("Enter the service name: ")
            username = input("Enter your username: ")

            deleted = delete_password(service, username, key)

            if deleted:
                print("Password deleted successfully!")
            else:
                print("Password not found for service and username")
        elif userchoice == "5":
            print("Goodbye!")
            break
        else:
            print("You did not enter a valid choice.")
else:
    print("Wrong password. Goodbye")