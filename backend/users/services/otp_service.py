import secrets
from django.db import transaction
from django.utils import timezone
from datetime import timedelta
from rest_framework import status
from ..models import User ,PasswordResetToken
from core_app.models import AgentApplication,EmailOTP
from core_app.constants import UserRole,ApprovalStatus
from django.contrib.auth import get_user_model
from  core_app.utils import generate_otp,send_otp_email

User=get_user_model()

def verify_otp_service(email, otp, purpose):
    otp_obj = EmailOTP.objects.filter(
        email=email,
        otp=otp,
        purpose=purpose
    ).first()

    if not otp_obj:
        return {
            "data": None,
            "errors": {"otp": "Invalid OTP"},
            "status": status.HTTP_400_BAD_REQUEST
        }

    if otp_obj.is_expired():
        otp_obj.delete()
        return {
            "data": None,
            "errors": {"otp": "OTP expired"},
            "status": status.HTTP_400_BAD_REQUEST
        }

    if purpose == "RESET":
        return _handle_reset(email, otp_obj)

    if purpose == "SIGNUP":
        return _handle_signup(email, otp_obj)

    if purpose == "AGENT":
        return _handle_agent(email, otp_obj)

    return {
        "data": None,
        "errors": {"purpose": "Invalid purpose"},
        "status": status.HTTP_400_BAD_REQUEST
    }

def _handle_reset(email, otp_obj):
    user = User.objects.filter(email=email).first()
    if not user:
        return {
            "data": None,
            "errors": {"email": "User not found"},
            "status": status.HTTP_404_NOT_FOUND
        }

    PasswordResetToken.objects.filter(user=user).delete()

    reset_token = secrets.token_urlsafe(32)
    PasswordResetToken.objects.create(user=user, token=reset_token)

    otp_obj.delete()

    return {
        "data": {
            "message": "OTP verified for password reset",
            "reset_token": reset_token
        },
        "errors": {},
        "status": status.HTTP_200_OK
    }

def _handle_signup(email, otp_obj):
    user = User.objects.filter(email=email).first()
    if not user:
        return {
            "data": None,
            "errors": {"email": "User not found"},
            "status": status.HTTP_404_NOT_FOUND
        }

    user.is_verified = True
    user.is_active = True
    user.save()

    otp_obj.delete()

    return {
        "data": {
            "message": "User email verified"
        },
        "errors": {},
        "status": status.HTTP_200_OK
    }

def _handle_agent(email, otp_obj):
    application = AgentApplication.objects.filter(email=email).first()
    if not application:
        return {
            "data": None,
            "errors": {"application": "Application not found"},
            "status": status.HTTP_404_NOT_FOUND
        }

    if application.email_verified:
        return {
            "data": {"message": "Email already verified"},
            "errors": None,
            "status": status.HTTP_200_OK
        }

    with transaction.atomic():
        application.email_verified = True
        application.is_active = True
        application.save()

        existing_user = User.objects.filter(email=email).first()

        if not existing_user:
            user=User.objects.create(
                email=application.email,
                name=application.full_name,
                role=UserRole.AGENT,
                approval_status=ApprovalStatus.PENDING,
                is_active=True,
                is_verified=True,
                profile_completed=True
            )
            user.password = application.password  
            user.save()

    otp_obj.delete()

    return {
        "data": {
            "message": "Agent email verified successfully. Account created"
        },
        "errors": {},
        "status": status.HTTP_201_CREATED
    }

def resend_otp_service(email,purpose):
    if not email or not purpose:
         return {
            "data": None,
            "errors": {"details": "Email and purpose are required"},
            "status": status.HTTP_400_BAD_REQUEST
        }
    recent_otp=EmailOTP.objects.filter(email=email,purpose=purpose,created_at__gte=timezone.now()-timedelta(minutes=1)).first()
    
    if recent_otp:
        return {
            "data": None,
            "errors": {"details": "Please wait before requesting another OTP"},
            "status": status.HTTP_429_TOO_MANY_REQUESTS
        }
    EmailOTP.objects.filter(email=email,purpose=purpose).delete()
    new_otp = generate_otp()
    EmailOTP.objects.create(email=email, otp=new_otp,purpose=purpose)
    expiry_time=timezone.now()+timedelta(minutes=1)
    
    try:
        send_otp_email(email, new_otp)
    except Exception as e:
        pass

    return {
        "data": {
            "message": "OTP resent successfully",
            "expires_at": expiry_time.isoformat()
        },
        "errors": {},
        "status": status.HTTP_200_OK
    }