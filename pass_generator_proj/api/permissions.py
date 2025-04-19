from rest_framework.permissions import BasePermission, SAFE_METHODS
from .models import PassGenModel, PasswordVault
from rest_framework.validators import ValidationError

class CustomIsLoginVaultPerm(BasePermission):

    def has_permission(self, request, view):
        print("Working perm 2")
        print(request.user)
        passvaul_user = PasswordVault.objects.get(user=request.user)
        if passvaul_user.is_logged_in == True:
            return True
        else:
            raise ValidationError({"message": "Sorry can't access this password please login to vault"}, 403)
        

    def has_object_permission(self, request, view, obj):
        print("working perm")
        if request.method in SAFE_METHODS:
            return 
        print(obj.user)
        if obj.user == request.user:
            return True