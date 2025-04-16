from rest_framework.permissions import BasePermission

class CustomIsLoginVaultPerm(BasePermission):

    def has_permission(self, request, view):
        print("Working perm 2")
        return True

    def has_object_permission(self, request, view, obj):
        print("working perm")
        return True