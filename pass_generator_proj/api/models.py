# Create your models here.
from django.db import models
from django.contrib.auth.models import User
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet



class PasswordVault(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    auth_token_master = models.BinaryField()
    salt = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_logged_in = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.auth_token_master}"

class PassGenModel(models.Model):
    pass_length = models.IntegerField()
    description = models.CharField(max_length=150)
    user = models.ForeignKey(User, on_delete=models.CASCADE,  related_name='pass_gen')
    encrypted_generated_password = models.BinaryField(max_length=150)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    vault = models.ForeignKey(PasswordVault, on_delete=models.CASCADE, related_name="pass_gene")

    def __str__(self):
        return f"{self.user}" 
    def generate_password(self):
        """Set the characters to be used to generate a random password from the 
        secrets module"""
        Uppercase_letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        lower_letters = 'abcdefghijklmnopqrstuvwxyz'
        special_chars = '!-+@#$%^&*()_><?/|\\";:.'
        digits = '0123456789'
        merged = ''
        generated_password = ''
        no_pass_generated = self.pass_length
        if self.pass_length:
            merged += Uppercase_letters
            merged += lower_letters 
            merged += special_chars
            merged += digits
            for x in range(0, no_pass_generated):
                generated_password += "".join(secrets.choice(merged))
           
        return generated_password
    
    
    
class SaveAccountsPass(models.Model):
    name_of_account = models.CharField(max_length=150)
    password_account = models.BinaryField()  # Store encrypted password
    description = models.CharField(max_length=200)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="save_accounts_pass")
    vault = models.ForeignKey(PasswordVault, on_delete=models.CASCADE, related_name="save_accounts_pass")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name_of_account}"


    
    
