from django.urls import path
from . import views
from rest_framework_simplejwt import views as jwt_views
from rest_framework.routers import DefaultRouter

router = DefaultRouter()

router.register(r"vault/generate-password", views.PassGenViewSet, basename='generate-password')

urlpatterns = [
    path('auth/register/', views.RegisterView.as_view(), name='register'),
    path('auth/login/', views.login_view, name='login'),
    path('auth/token/refresh/', jwt_views.TokenRefreshView.as_view(), name="token_refresh"),
    path('auth/logout/', views.logout_view, name='logout'),
    path('user/vault/create/', views.create_pass_vault, name='create_pass_vault'),
    path('user/vault/login/', views.vault_login, name='vault_login'),
]+router.urls