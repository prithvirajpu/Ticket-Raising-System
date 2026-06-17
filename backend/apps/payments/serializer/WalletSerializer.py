from rest_framework import serializers
from apps.payments.models import Wallet

class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model=Wallet
        fields=['id','balance','created_at','updated_at']