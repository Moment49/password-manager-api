from django.db import models
# Create your models here.
from django.contrib.auth.models import User


class PassGenModel(models.Model):
    pass_length = models.IntegerField()
    description = models.CharField(max_length=150)
    user = models.ForeignKey(User, on_delete=models.CASCADE,  related_name='pass_gen')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user}"

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
    master_password = models.CharField(max_length=250)
    accounts = models.ForeignKey(SaveAccountsPass, on_delete=models.CASCADE, related_name='pass_vault')
    pass_gen = models.ForeignKey(PassGenModel, on_delete=models.CASCADE, related_name='pass_vault')

    def __str__(self):
        return f"{self.master_password}"
