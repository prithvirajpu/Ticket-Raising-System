from django.contrib.auth import authenticate
from rest_framework import serializers
from .models import User
from core_app.constants import ApprovalStatus,UserRole
from core_app.models import AgentApplication
from django.contrib.auth.hashers import make_password,check_password

class LoginSerializer(serializers.Serializer):
    email=serializers.EmailField()
    password=serializers.CharField(write_only=True)

    def validate(self,data):
        user=authenticate(
            email=data['email'],
            password=data['password']
        )
        try:
            if not user:
                raise serializers.ValidationError('Invalid credentials')
            if not user.is_verified:
                raise serializers.ValidationError('Email not verified')
            if user.approval_status != ApprovalStatus.APPROVED:
                raise serializers.ValidationError('Account pending admin approval')
            if not user.is_active:
                raise serializers.ValidationError('Account is inactive')

            data['user'] = user  
        except AgentApplication.DoesNotExist:
            pass
        if not user:
            raise serializers.ValidationError('Invalid credentials')
        # for fake
        if user.role!= UserRole.USER:
            if user.approval_status!=ApprovalStatus.APPROVED:
                raise serializers.ValidationError('Account pending admin approval')
        if not user.is_active:
            raise serializers.ValidationError('Account is inactive')
        data['user']=user
        return data

class UserApprovalSerializer(serializers.ModelSerializer):
    class Meta:
        model=AgentApplication
        fields = ['id', 'full_name', 'email', 'phone', 'status']

class ClientSignupSerializer(serializers.ModelSerializer):
    email=serializers.EmailField()
    password=serializers.CharField(write_only=True)
    
    class Meta:
        model=User
        fields=['email','password']
    def create(self,validated_data):
        user=User.objects.create_user(
                    email=validated_data['email'],
                    password=validated_data['password'],
                    role=UserRole.CLIENT,
                    approval_status=ApprovalStatus.APPROVED,
                    is_active=False,
                    is_verified=False
                    )
        return user

class AgentSignupSerializer(serializers.ModelSerializer):
    password=serializers.CharField(write_only=True)
    confirm_password=serializers.CharField(write_only=True)

    class Meta:
        model=AgentApplication
        fields=['full_name','email','phone','skills','resume','certificates','password','confirm_password']

    def validate(self,data):
        if data['password']!=data['confirm_password']:
            raise serializers.ValidationError('Passwords do not match')
        return data
    
    def create(self,validated_data):
        validated_data.pop('confirm_password')
        password=validated_data.pop('password')
        validated_data['password']=make_password(password)
        validated_data['email_verified'] = False
        validated_data['status'] ='PENDING'
        return AgentApplication.objects.create(**validated_data)

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)