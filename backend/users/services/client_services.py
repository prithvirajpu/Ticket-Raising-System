from core_app.models import AgentApplication,EmailOTP
from core_app.utils import generate_otp,send_otp_email
from datetime import timedelta
from django.utils import timezone
from rest_framework import status

def client_signup_service(serializer):
    email=serializer.validated_data['email']
    serializer.save()
    EmailOTP.objects.filter(email=email,purpose='SIGNUP').delete()

    otp_code=generate_otp()
    EmailOTP.objects.create(email=email,otp=otp_code,purpose='SIGNUP')

    expiry_time=timezone.now()+timedelta(minutes=1)
    send_otp_email(email,otp_code)
    
    return {'message':"OTP sent to your email",'expires_at':expiry_time.isoformat(),'status':status.HTTP_200_OK}