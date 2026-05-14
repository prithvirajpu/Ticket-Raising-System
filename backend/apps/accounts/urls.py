from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (LoginView,AgentSignupView,ClientSignupView,GoogleClientAuthView,VerifyOTPView,
                ResendOTPView,ResendOTPView,ResetPasswordView, CheckUserExistsView,
                  SSOLoginAPIView  )

urlpatterns = [
    path('sso-login/',SSOLoginAPIView.as_view()),

    path('login/',LoginView.as_view()),
    path('signup/agent/',AgentSignupView.as_view()),
    path('signup/client/',ClientSignupView.as_view()),
    path("google/", GoogleClientAuthView.as_view()),
    path('verify-otp/',VerifyOTPView.as_view()),
    path('resend-otp/',ResendOTPView.as_view()),
    path('forgot-password/',ResendOTPView.as_view()),
    path('reset-password/',ResetPasswordView.as_view()),
    path("check-user/", CheckUserExistsView.as_view()),
    path('token/refresh/', TokenRefreshView.as_view()),
]