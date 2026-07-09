from rest_framework import serializers
from apps.payments.models import Wallet

class WalletSerializer(serializers.ModelSerializer):
    is_stripe_connected=serializers.SerializerMethodField()
    class Meta:
        model=Wallet
        fields=['id','balance','is_stripe_connected','created_at','updated_at']

    def get_is_stripe_connected(self,obj):
        return bool(obj.user.stripe_connect_account_id)