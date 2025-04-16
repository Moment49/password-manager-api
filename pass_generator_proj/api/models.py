# Create your models here.
from django.db import models
from django.contrib.auth.models import User
import bcrypt
import random


class PassGenModel(models.Model):
    pass_length = models.IntegerField()
    description = models.CharField(max_length=150)
    user = models.ForeignKey(User, on_delete=models.CASCADE,  related_name='pass_gen')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user}"
    def generate_password(self):
         # Set the characters to be used to generate a random password
        Uppercase_letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        lower_letters = 'abcdefghijklmnopqrstuvwxyz'
        special_chars = '!-+@#$%^&*()_><?/|\\";:.'
        digits = '0123456789'
        merged = ''
        generated_password = ''
        no_pass_generated = 1
        if self.pass_length:
            merged += Uppercase_letters
            merged += lower_letters 
            merged += special_chars
            merged += digits
            for x in range(no_pass_generated):
                generated_password = "".join(random.sample(merged, k=self.pass_length))
        return generated_password

    def encrypt_generated_password(self):
        ...
    
    

class SaveAccountsPass(models.Model):
    name_of_account = models.CharField(max_length=150)
    password_account = models.CharField(max_length=200)
    description = models.CharField(max_length=200)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="save_accounts_pass")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name_of_account}"

class PasswordVault(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    hashed_master_password = models.BinaryField(max_length=250)
    accounts = models.ForeignKey(SaveAccountsPass, on_delete=models.CASCADE, related_name='pass_vault', null=True, blank=True)
    pass_gen = models.ForeignKey(PassGenModel, on_delete=models.CASCADE, related_name='pass_vault', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_logged_in = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.hashed_master_password}"
    
    def hash_password(self, password):
        """This method is to hash the 
            the password for the vault
        """
        # generate a random salt
        salt = bcrypt.gensalt(12)
        hashed_master_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        self.hashed_master_password = hashed_master_password
        
        return self.hashed_master_password
    
    def verify_password(self, input_password):
        """This method is to verify the hashed master password
            for the vault
        """
        # Encode the input_password and hashed_master_password and return it
        return bcrypt.checkpw(input_password.encode('utf-8'), self.hashed_master_password)
