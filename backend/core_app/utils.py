import random
from django.core.mail import send_mail
from django.conf import settings

def generate_otp():
    return str(random.randint(100000,999999))

def send_otp_email(email,otp):
    subject='Your Verification Code'
    message=f'Your OTP code is {otp}. It expires in 2 minutes..'
    send_mail(subject,message,settings.EMAIL_HOST_USER,[email],fail_silently=False)