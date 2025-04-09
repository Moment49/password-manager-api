from rest_framework import generics, status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from django.contrib.auth.models import User
from api.serializers import RegisterSerializer, LoginSerializer, LogoutSerializer
from django.contrib.auth import authenticate,login
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.viewsets import ModelViewSet


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

            return Response({"message":"User not authenticated"}, status=status.HTTP_401_UNAUTHORIZED)



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
                return Response({"message":"logout successful"}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"message":"bad token"}, status=status.HTTP_400_BAD_REQUEST)

class PassGenViewSet(ModelViewSet):
    """This is a view to perform crud operations 
        for password Generators for users
    """

