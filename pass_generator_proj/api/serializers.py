from django.contrib.auth.models import User
from rest_framework import serializers
from .models import PassGenModel, PasswordVault, SaveAccountsPass
import base64

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'username']


class RegisterSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)
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
    user = UserSerializer(read_only=True)
    class Meta:
        model = PassGenModel
        fields = ['id', 'pass_length', 'description', 'user', 'created_at', 'encrypted_generated_password']
        read_only_fields = ['user']

    def validate(self, attrs):
        if attrs['pass_length'] < 10:
            raise serializers.ValidationError('You must select a password length greater than 7')
        if attrs['description'] == '':
            raise serializers.ValidationError('Description for the password generated must not be empty')
        return attrs
    
    def to_internal_value(self, data):
        validated_data = super().to_internal_value(data)
        encrypted_password_b64 = data.get('encrypted_generated_password')
        if encrypted_password_b64:
            try:
                # Decode the base64 string to bytes and add it to validated_data
                validated_data['encrypted_generated_password'] = base64.b64decode(encrypted_password_b64)
            except Exception:
                    raise serializers.ValidationError({'encrypted_generated_password': 'Invalid base64 string.'})
        else:
            raise serializers.ValidationError({'encrypted_generated_password': 'This field is required.'})

        return validated_data
     
    
    # def to_representation(self, instance):
    #     return super().to_representation(instance)
    
    def create(self, validated_data):
        pass_length = validated_data['pass_length']
        description = validated_data['description']
        encrypted_generated_password = validated_data.get('encrypted_generated_password')
        print(encrypted_generated_password)
        print(pass_length)
        user = self.context.get("user")
        
        # Get the user's vault
        vault = PasswordVault.objects.get(user=user)
        
        password_gene = PassGenModel.objects.create(
            pass_length=pass_length, 
            description=description, 
            user=user,
            vault=vault,
            encrypted_generated_password=encrypted_generated_password

        )
        
        password_gene.save()
        return password_gene
       


class PasswordVaultSerializer(serializers.ModelSerializer):
    auth_token_master = serializers.CharField(write_only=True)
    salt = serializers.CharField(write_only=True)
    user = UserSerializer(read_only=True)

    class Meta:
        model = PasswordVault
        fields = ['auth_token_master', 'salt', 'user']
    

    def to_internal_value(self, data):
        """This takes in the data sent and converts it to 
        the internal datatype of the model"""
        validated_data = super().to_internal_value(data)
        data['auth_token_master'] = base64.b64decode(data['auth_token_master'])
        data['salt'] = base64.b64decode(data['salt'])
        return validated_data
    
    def to_representation(self, instance):
        return super().to_representation(instance)
    
    def create(self, validated_data):
        auth_token_master = validated_data['auth_token_master']
        salt = validated_data['salt']
        # get the user object from the request context password to the serializer
        user = self.context.get('user')
        if PasswordVault.objects.filter(user=user).exists():
            raise serializers.ValidationError(f"Vault already exists for the user {user}")
        else:
            vault = PasswordVault.objects.create(auth_token_master=auth_token_master, salt=salt, user=user)
            vault.save()
    
        return vault

class PasswordVaultLoginSerializer(serializers.Serializer):
    auth_token_master = serializers.CharField(write_only=True)
    salt = serializers.CharField(write_only=True)
    

    def to_internal_value(self, data):
        """This takes in the data sent and converts it to 
        the internal datatype of the model"""
        super().to_internal_value(data)
        data['auth_token_master'] = base64.b64decode(data['auth_token_master'])
        data['salt'] = base64.b64decode(data['salt'])
        return data
    
    def to_representation(self, instance):
        return super().to_representation(instance)

