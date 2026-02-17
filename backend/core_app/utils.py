import random
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings

User = get_user_model()

def generate_otp():
    return str(random.randint(100000,999999))

def send_otp_email(email,otp):
    subject='Your Verification Code'
    message=f'Your OTP code is {otp}. It expires in 2 minutes..'
    send_mail(subject,message,settings.EMAIL_HOST_USER,[email],fail_silently=False)

def generate_jwt_token(user):
    refresh = RefreshToken.for_user(user)
    return {
        'access': str(refresh.access_token),
        'refresh': str(refresh),
    }

def generate_access_token_only(user):
    refresh = RefreshToken.for_user(user)
    return str(refresh.access_token)