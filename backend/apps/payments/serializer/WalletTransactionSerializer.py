from rest_framework import serializers
from apps.payments.models import WalletTransaction

class WalletTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model=WalletTransaction
        fields = [
            "id",
            "transaction_type",
            "amount",
            "description",
            "created_at",
        ]