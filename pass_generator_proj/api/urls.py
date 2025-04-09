from django.urls import path
from . import views
from rest_framework_simplejwt import views as jwt_views

urlpatterns = [
    path('auth/register/', views.RegisterView.as_view(), name='register'),
    path('auth/login/', views.login_view, name='login'),
    path('auth/token/refresh', jwt_views.TokenRefreshView.as_view(), name="token_refresh"),
    path('auth/logout', views.logout_view, name='logout')
]