from django.contrib.auth import authenticate
from rest_framework import serializers
from .models import User
from core_app.constants import ApprovalStatus,UserRole

class LoginSerializer(serializers.Serializer):
    email=serializers.EmailField()
    password=serializers.CharField(write_only=True)

    def validate(self,data):
        user=authenticate(
            email=data['email'],
            password=data['password']
        )
        if not user:
            raise serializers.ValidationError('Invalid credentials')
        #for fake
        if user.role!= UserRole.USER:
            if user.approval_status!=ApprovalStatus.APPROVED:
                raise serializers.ValidationError('Account pending admin approval')
        if not user.is_active:
            raise serializers.ValidationError('Account is inactive')
        data['user']=user
        return data

class UserApprovalSerializer(serializers.ModelSerializer):
    role=serializers.ChoiceField(choices=[UserRole.AGENT,UserRole.MANAGER,UserRole.TEAM_LEAD])
    class Meta:
        model=User
        fields=['id','role']