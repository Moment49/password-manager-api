from django.contrib.auth.models import User
from rest_framework import serializers
from .models import PassGenModel, PasswordVault, SaveAccountsPass

class RegisterSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'password', 'confirm_password']
    

    def validate(self, attrs):
        password = attrs['password']
        confirm_password = attrs['confirm_password']
        if len(password) < 8 or len(confirm_password) < 8:
            raise serializers.ValidationError("Sorry Password must be greater than 8 characters")
        if password != confirm_password:
            raise serializers.ValidationError("Sorry both password must match")
        
        return attrs
    

    def create(self, validated_data):
        user = User.objects.create_user(first_name=validated_data['first_name'],
                                        last_name=validated_data['last_name'],
                                        username=validated_data['username'])
        
        user.set_password(validated_data['password'])
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)


class LogoutSerializer(serializers.Serializer):
    token = serializers.CharField()


class PassGenSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = PassGenModel
        fields = ['id', 'pass_length', 'description', 'user', 'created_at']
    