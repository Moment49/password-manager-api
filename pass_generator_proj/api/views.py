from rest_framework import generics, status, views
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from django.contrib.auth.models import User
from api.serializers import (RegisterSerializer, LoginSerializer, LogoutSerializer,
                             PasswordVaultSerializer,PassGenSerializer, PasswordVaultLoginSerializer)
from django.contrib.auth import authenticate,login
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.viewsets import ModelViewSet
from .models import PasswordVault, SaveAccountsPass, PassGenModel
from .permissions import CustomIsLoginVaultPerm
import base64


# Create your views here.
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

@api_view(['POST'])
@authentication_classes([JWTAuthentication, SessionAuthentication])
def login_view(request):
    if request.method == 'POST':
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            username = serializer.validated_data.get('username')
            password = serializer.validated_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                # Implement a jwt token-based auth
                refresh = RefreshToken.for_user(user)
                access_token = refresh.access_token
                # Add custom data to the access token
                access_token['user_id']  = user.pk
                access_token['username'] = user.username

                return Response({"token":{
                    "access_token": str(access_token),
                    "refresh_token":str(refresh)
                },"message":"login successfully"}, status=status.HTTP_200_OK)

            return Response({"message":"Invalid Credentials user not authenticated"}, status=status.HTTP_401_UNAUTHORIZED)



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    if request.method == "POST":
        serializer = LogoutSerializer(data = request.data)
        if serializer.is_valid(raise_exception=True):
            """
            The refresh token associated with the user
            is passed to the body of the request and blacklisted
            """
            try:
                refresh_token = serializer.validated_data['token']
                print(refresh_token)
                token = RefreshToken(refresh_token)
                token.blacklist()
                # Also Logout the user from the vault once the logout from the application
                user_pass_vault = PasswordVault.objects.get(user=request.user)
                if user_pass_vault.is_logged_in == True:
                    user_pass_vault.is_logged_in = False
                    user_pass_vault.save()
                return Response({"message":"logout successful"}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"message":"bad token"}, status=status.HTTP_400_BAD_REQUEST)

class PassGenViewSet(ModelViewSet):
    """This is a view to perform crud operations 
        for password Generators for users
    """
    serializer_class = PassGenSerializer
    queryset = PassGenModel.objects.all()
    permission_classes = [IsAuthenticated, CustomIsLoginVaultPerm]

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['user'] = self.request.user
        return context

class PassVaultSaltView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            vault = PasswordVault.objects.get(user=request.user)
        except PasswordVault.DoesNotExist:
            return Response({"message":"Sorry Invalid salt. Vault not found"}, status=status.HTTP_404_NOT_FOUND)
        
        salt_baseb4 = base64.b64encode(vault.salt).decode('utf-8')
        return Response({"salt":salt_baseb4}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_pass_vault(request):
    if request.method == 'POST':
        serializer = PasswordVaultSerializer(data=request.data, context = {"user":request.user})
       
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message":"Password Vault created successfully"}, status=status.HTTP_201_CREATED)
        else:
            return Response({"message":"something broke down..vault not created"}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def vault_login(request):
    if request.method == 'POST':
        serialzer = PasswordVaultLoginSerializer(data=request.data)
        if serialzer.is_valid(raise_exception=True):
            vault = PasswordVault.objects.get(user=request.user)
            auth_token_master = serialzer.validated_data['auth_token_master']
            salt = serialzer.validated_data['salt']
            if vault.auth_token_master == auth_token_master and vault.salt == salt:
                # set the vault as logged in
                vault.is_logged_in = True
               
                vault.save()
                return Response({"message":"Master password correct.. Login to Vault successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({"message":"error login to vault failed"}, status=status.HTTP_401_UNAUTHORIZED)
            
        return Response({"message":"Invalid password"}, status=status.HTTP_400_BAD_REQUEST)
            


