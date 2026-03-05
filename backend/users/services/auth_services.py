from rest_framework import status
from ..models import PasswordResetToken
from core_app.utils import generate_otp,send_otp_email
from core_app.models import EmailOTP
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
User=get_user_model()

def reset_password_service(reset_token,new_password):
    token_obj=PasswordResetToken.objects.filter(token=reset_token).first()

    if not token_obj:
        return {'error': 'Invalid reset token','status':status.HTTP_404_NOT_FOUND}
    
    if token_obj.is_expired():
        token_obj.delete()
        return {'error': 'OTP expired', 'status':status.HTTP_400_BAD_REQUEST}
    user=token_obj.user
    if user.check_password(new_password):
        return {'error':'New password cannot be the same as the old password'
                        ,'status':status.HTTP_400_BAD_REQUEST}
    
    user.set_password(new_password)
    user.save()
    token_obj.delete()
    return {'message':'Password reset successfull','status':status.HTTP_200_OK}

def forgot_password_service(email):
    user = User.objects.filter(email__iexact=email).first()
    if not user:
        return {"error": "User not found",
            'status':status.HTTP_400_BAD_REQUEST}

    recent_otp = EmailOTP.objects.filter(
        email=email,
        purpose='RESET',
        created_at__gte=timezone.now() - timedelta(minutes=1)
    ).first()
    if recent_otp:
        expiry_time = recent_otp.created_at + timedelta(minutes=1)
    else:
        EmailOTP.objects.filter(
            email=email,
            purpose='RESET'
        ).delete()
        otp = generate_otp()
        EmailOTP.objects.create(
            email=email,
            otp=otp,
            purpose='RESET'
        )
        send_otp_email(email, otp)
        expiry_time = timezone.now() + timedelta(minutes=1)
    return {
            "message": "OTP sent successfully",
            "expires_at": expiry_time.isoformat(),
            'status':status.HTTP_200_OK
    }