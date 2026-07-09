from rest_framework import serializers
from apps.payments.models import WithdrawalRequest

class withdrawal_serializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source='user.email',read_only=True)
    user_role = serializers.CharField(source='user.role',read_only=True)
    
    class Meta:
        model= WithdrawalRequest
        fields= "__all__"