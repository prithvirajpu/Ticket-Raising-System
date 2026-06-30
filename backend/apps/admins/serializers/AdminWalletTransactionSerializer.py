from rest_framework import serializers
from apps.payments.models import WalletTransaction

class AdminWalletTransactionSerializer(serializers.ModelSerializer):
    user_name= serializers.CharField(source='user.name',read_only=True)
    user_email= serializers.CharField(source='user.email',read_only=True)
    balance= serializers.DecimalField(source='wallet.balance',max_digits=12,decimal_places=2,read_only=True)

    class Meta:
        model= WalletTransaction
        fields=[
            "id",
            "user_name",
            "user_email",
            "transaction_type",
            "amount",
            "balance",
            "description",
            "created_at",
        ]