import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.contrib.auth.models import User
from api.models import PasswordVault
import requests
import secrets
from cryptography.fernet import Fernet


"""This is a script file to simulate the frontend for generating the key, token and salt 
    for the master pasword as well as encrypting and decrypting the data and sending it to the backend
 """

def generate_key_token(master_password:str):
    """This is a method that will take in the 
    master password and generate a token key for the user"""
    # Generate the salt
    salt = os.urandom(16)
    # Derive a key from the master password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000
    )
    key = kdf.derive(master_password.encode())

    # Create the token hash from the key which will be used to authenticate the user
    token_hash = hashes.Hash(hashes.SHA256())
    token_hash.update(key)
    token_hash = token_hash.finalize()

    # convert the encoded binary data (token and salt) to a base64-encoded data
    token_hash_base64 = base64.b64encode(token_hash).decode('utf-8')
    salt_base64 = base64.b64encode(salt).decode('utf-8')
    key = base64.b64encode(key).decode('utf-8')
   
    return key, token_hash_base64, salt_base64


def regenerate_key_token(master_password:str, salt:str):
    salt = base64.b64decode(salt)
    print(salt)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000
    )
    key = kdf.derive(master_password.encode())

    # Create the token hash that will be sent to the backend for verification
    token_hash = hashes.Hash(hashes.SHA256())
    token_hash.update(key)
    token_hash = token_hash.finalize()

    # convert the encoded binary data (token and salt) to a base64-encoded data
    token_hash_base64 = base64.b64encode(token_hash).decode('utf-8')
    salt_base64 = base64.b64encode(salt).decode('utf-8')
    key = base64.b64encode(key).decode('utf-8')

    # Test
    return key, token_hash_base64, salt_base64


def run():
    # Simulate the login process to the application from the frontend
    message = "Simulate the login process to the application from the frontend"
    message+="\n1. Login to the application"
    message+="\n2. Exit the application "
    message+= "\nSelect the action you want to perform: "
    islogin = False

    # Save the jwt token recieved from the backend
    jwt_token = None

    while not islogin:
    # Get the master password from the user assume the user is already authenticated
    # Note: The Jwt token recieved from the backend will be used to send the request to the backend
     # We will first simulate the normal login process to the application here
      
        login_choice = input(message)
        if login_choice == "2":
            print("Exiting the application")
            islogin = False
            break
        if login_choice == "1":
            print("Please enter yout login details")
            username = input("Enter the username: ")
            password = input("Enter the password: ")
            
            # Send the login details to the backend to verify credentials and return the token
            res =requests.post("http://127.0.0.1:8000/api/auth/login/", json={"username":username, "password":password})
            if res.status_code == 200:
                print("login to application successful")
                token = res.json()['token']
                jwt_token = token['access_token']
                print(jwt_token)

                # Create the master password vault for the user
                isVaultLogin = False
                print("Vault creation and login process check..Background process running")
                
                while not isVaultLogin:
                     # Get the master password for the vault from the user
                    master_password = input("Enter the master password for the vault: ")
                    if len(master_password) < 10:
                        print("Master password should be greater than 10 characters")
                        continue

                    # Get the salt from the backend for the user
                    res = requests.get("http://127.0.0.1:8000/api/user/vault/salt", headers={'Authorization':f"Bearer {jwt_token}"})
                    print(res.json())

                    if res.status_code == 200:
                        salt = res.json()['salt']
                        # Renegrate the key, token and salt from the master password and send to the backend
                        key, auth_token_master, salt = regenerate_key_token(master_password, salt)
                        print(f"key:{key}, token:{auth_token_master}, salt:{salt}")
                        res = requests.post("http://127.0.0.1:8000/api/user/vault/login/",
                                            json={"auth_token_master":auth_token_master, "salt":salt}, headers={'Authorization':f"Bearer {jwt_token}"})
                        if res.status_code == 200:
                            print("Vault login successful")
                            isVaultLogin = True
                            islogin = True
                            # TODO: Select an operation to perform for the password generation CRUD operations
                            print("Select the operation you want to perform: ")
                            print("1. Generate password")
                            print("2. Updated Password")
                            print("3. Show Password")
                            print("4. Show all passwords")
                            print("5. Delete Password")

                            operation = input("Enter the operation you want to perform: ")
                            if operation == "1":
                                print("Generate password")
                                password_len = int(input("Enter password length: "))
                                password_desc = input("Enter password description : ")
                                """Set the characters to be used to generate a random password from the 
                                secrets module"""
                                Uppercase_letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                                lower_letters = 'abcdefghijklmnopqrstuvwxyz'
                                special_chars = '!-+@#$%^&*()_><?/|\\";:.'
                                digits = '0123456789'
                                merged = ''
                                generated_password = ''
                                if password_len:
                                    merged += Uppercase_letters
                                    merged += lower_letters 
                                    merged += special_chars
                                    merged += digits
                                    for x in range(0, password_len):
                                        generated_password += "".join(secrets.choice(merged))
                                print(f"Password Generated: {generated_password}")
                                # Encrypt password
                                f = Fernet(key)
                                encrypted_password = f.encrypt(generated_password.encode('utf-8'))
                                # Convert to a base64 string
                                encrypted_password_b64string = base64.b64encode(encrypted_password).decode('utf-8')
                                print(encrypted_password_b64string)
                                # Make an api call to the backend to create and save the new password
                                res = requests.post("http://127.0.0.1:8000/api/vault/generate-password/", 
                                              json={"pass_length":password_len, "description":password_desc, 
                                              "encrypted_generated_password":encrypted_password_b64string},
                                            headers={'Authorization':f'Bearer {jwt_token}'})
                                
                                if res.status_code == 201:
                                    print("Password generated successfully and lets just say its been decrypted and show to the user")
                                else:
                                    print("errors")
                            elif operation == "2":
                                ...
                            elif operation == "3":
                                ...
                            elif operation == "4":
                                ...
                            elif operation == "5":
                                ...

                          
                        else:
                            print("Invalid master password. Please try again.")
                            master_password = input("Enter the master password for the vault: ")
                    else:
                        print("Creating the master password vault for the first time for logged in user")
                        isCreateVault = False
                        while not isCreateVault:
                            # Get the master password for the vault from the user
                            master_password = input("Create a new master password for the vault: ")
                            if len(master_password) < 10:
                                print("Master password should be greater than 10 characters")
                                continue
                                
                            # Genegrate the key, token and salt from the master password and send to the backend
                            key, auth_token_master, salt = generate_key_token(master_password)
                            print(f"key:{key}, token:{auth_token_master}, salt:{salt}")
                            res = requests.post("http://127.0.0.1:8000/api/user/vault/create/",
                                                json={"auth_token_master":auth_token_master, "salt":salt}, headers={'Authorization':f"Bearer {jwt_token}"})
                            if res.status_code == 201:
                                print("Vault Creation successful")
                                isCreateVault = True
                                isVaultLogin = False
                                islogin = True
                                
                            else:
                                print("Failed to create vault. Please try again.")
            else:
                print("login failed")
            

if __name__ == "__main__":
    run()
       

