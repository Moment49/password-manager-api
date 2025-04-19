import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ..api.models import PasswordVault
from django.contrib.auth.models import User
import requests

"""This is a script file to simulate the frontend for generating the key, token and salt 
    for the master pasword
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
   
    return key, token_hash_base64, salt_base64


def regenerate_key_token(master_password:str, salt:str):
    salt = base64.b64decode(salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=12,
        salt=salt
        iterations=1_200_000
    )
    key = kdf.derive(master_password.encode())
    


def run():
    master_password = input("Enter the master password:")
    if len(master_password) < 10:
        raise Exception("Master password should be greater than 10 characters")
    key, token_hash, salt = generate_key_token(master_password)
    print(key, token_hash, salt)

    # Lets try to regenerate the token again to match it but this time we can use the 
    # get request to see if the user is logged in






if __name__ == "__main__":
    run()
       

