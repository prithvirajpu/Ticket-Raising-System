from django.contrib.auth import authenticate
from rest_framework import serializers
from .models import User
from core_app.constants import ApprovalStatus,UserRole
from core_app.models import AgentApplication,AgentCertificate
from django.contrib.auth.hashers import make_password,check_password

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(
            email=data['email'],
            password=data['password']
        )
        
        if not user:
            raise serializers.ValidationError('Invalid credentials')
        
        if not user.is_verified:
            raise serializers.ValidationError('Email not verified')
        
        if not user.is_active:
            raise serializers.ValidationError('Account is inactive')
        
        # 3. NON-USER roles need approval
        if user.role != UserRole.USER:
            if user.approval_status != ApprovalStatus.APPROVED:
                raise serializers.ValidationError('Account pending admin approval')
        
        data['user'] = user
        return data

class UserApprovalSerializer(serializers.ModelSerializer):
    class Meta:
        model=AgentApplication
        fields = ['id', 'email', 'phone', 'status']

class ClientSignupSerializer(serializers.ModelSerializer):
    email=serializers.EmailField()
    password=serializers.CharField(write_only=True)
    
    class Meta:
        model=User
        fields=['email','password']
    def validate(self, data):
        if User.objects.filter(email=data['email']).exists() or AgentApplication.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError('Email already exist')
        return data
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
    certificates = serializers.ListField(
        child=serializers.FileField(),
        write_only=True,
        required=False
    )
    class Meta:
        model=AgentApplication
        fields=['full_name','email','phone','skills','resume','certificates','password','confirm_password']

    def validate(self,data):
        if User.objects.filter(email=data['email']).exists() or AgentApplication.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError('Email already exist')
        if data['password']!=data['confirm_password']:
            raise serializers.ValidationError('Passwords do not match')
        return data
    
    def create(self, validated_data):
        certificates = validated_data.pop('certificates', [])
        validated_data.pop("confirm_password")
        password = validated_data.pop("password")
        validated_data["password"] = make_password(password)
        validated_data["status"] = "PENDING"

        agent = AgentApplication.objects.create(**validated_data)

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

