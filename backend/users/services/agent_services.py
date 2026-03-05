from django.contrib.auth import get_user_model
from core_app.utils import generate_otp,send_otp_email
from ..serializers import AgentSignupSerializer
from core_app.models import AgentApplication,EmailOTP
from datetime import timedelta
from rest_framework import status
from django.utils import timezone

def agent_signup_service(data):
    email = data.get("email")
    if not email:
        return {"error": "Email is required.", 'status':status.HTTP_400_BAD_REQUEST}
    existing_agent = AgentApplication.objects.filter(email=email).first()
    if existing_agent:
        serializer = AgentSignupSerializer(existing_agent, data=data, partial=True)
    else:
        serializer = AgentSignupSerializer(data=data) 
    serializer.is_valid(raise_exception=True)
    serializer.save()
    is_new=existing_agent is None

    EmailOTP.objects.filter(email=email, purpose="AGENT").delete()
    otp = generate_otp()
    EmailOTP.objects.create(email=email, otp=otp, is_verified=False, purpose="AGENT")
    expiry_time = timezone.now() + timedelta(minutes=1)
    send_otp_email(email, otp)
    if is_new:
        message = "Agent application submitted. OTP sent to email for verification."
        response_status =status.HTTP_201_CREATED
    else:
        message="Existing agent found. OTP resent for email verification."
        response_status=status.HTTP_200_OK
    return {"message": message,
                    "expires_at": expiry_time.isoformat(),'status':response_status}