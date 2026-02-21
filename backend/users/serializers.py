from django.contrib.auth import authenticate
from rest_framework import serializers
from .models import User
from core_app.constants import ApprovalStatus,UserRole
from core_app.models import AgentApplication,AgentCertificate
from django.contrib.auth.hashers import make_password,check_password
from django.db import transaction
import logging

logger=logging.getLogger(__name__)


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    from django.contrib.auth import authenticate

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        # Try to authenticate in User model first
        user = authenticate(email=data['email'], password=data['password'])

        if user:
            # Existing user logic
            if not user.is_verified:
                raise serializers.ValidationError('Email not verified')
            if not user.is_active:
                raise serializers.ValidationError('Account is inactive')
            if user.role != UserRole.USER and user.approval_status != ApprovalStatus.APPROVED:
                raise serializers.ValidationError('Waiting for admin approval')
            
            data['user'] = user
            return data

        # If no User exists, check AgentApplication
        application = AgentApplication.objects.filter(email=data['email']).first()
        if application:
            if application.status != "APPROVED":
                raise serializers.ValidationError('Waiting for admin approval')
            if not application.email_verified:
                raise serializers.ValidationError('Email not verified')
        
        raise serializers.ValidationError('Invalid credentials')

class UserApprovalSerializer(serializers.ModelSerializer):
    class Meta:
        model=AgentApplication
        fields = ['id', 'email', 'phone', 'status','full_name','applied_at']

class ClientSignupSerializer(serializers.ModelSerializer):
    email=serializers.EmailField()
    password=serializers.CharField(write_only=True)
    
    class Meta:
        model=User
        fields=['email','password']
    def validate(self, data):
        email=data.get('email')
        existing_user=User.objects.filter(email=email).first()
        if existing_user and existing_user.is_verified:
            raise serializers.ValidationError('Email already exist')
        
        existing_application = AgentApplication.objects.filter(email=email).first()
        if existing_application and existing_application.email_verified:
            raise serializers.ValidationError("Email already used as Agent")    
        
        return data
    def create(self, validated_data):
        password = validated_data.pop("password")

        existing_user = User.objects.filter(email=validated_data["email"]).first()

        if existing_user and not existing_user.is_verified:
            existing_user.set_password(password)
            existing_user.save()
            return existing_user

        user = User.objects.create_user(
            password=password,
            role=UserRole.CLIENT,
            approval_status=ApprovalStatus.APPROVED,
            is_active=False,
            is_verified=False,
            **validated_data
        )

        return user

class AgentSignupSerializer(serializers.ModelSerializer):
    password=serializers.CharField(write_only=True)
    confirm_password=serializers.CharField(write_only=True)
    certificates = serializers.ListField(
        child=serializers.FileField(),
        write_only=True,
        required=False
    )
    class Meta:
        model=AgentApplication
        fields=['full_name','email','phone','skills','resume','certificates','password','confirm_password']

    def validate(self, data):
        email = data.get('email')
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email already exist")
        existing_user = User.objects.filter(email=email).first()

        if existing_user and existing_user.is_verified:
            raise serializers.ValidationError("Email already exist")
        
        if data.get('password') != data.get('confirm_password'):
            raise serializers.ValidationError("Passwords do not match")
        return data
    
    def create(self, validated_data):
        certificates = validated_data.pop('certificates', [])
        validated_data.pop("confirm_password")
        password = validated_data.pop("password")

        with transaction.atomic():

            agent = AgentApplication.objects.create(
                **validated_data,
                password=make_password(password),
                status="PENDING",
                email_verified=False,
                is_active=False
            )
            for cert in certificates:
                AgentCertificate.objects.create(agent=agent, file=cert)

        return agent

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    purpose = serializers.CharField(required=False)


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField(write_only=True)

