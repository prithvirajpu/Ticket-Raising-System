from django.db.models import Sum
from rest_framework import serializers

from apps.payments.models import WalletTransaction


class SalaryDistributionSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(
        source="wallet.user.name",
        read_only=True
    )

    user_email = serializers.EmailField(
        source="wallet.user.email",
        read_only=True
    )

    role = serializers.CharField(
        source="wallet.user.role",
        read_only=True
    )

    salary = serializers.SerializerMethodField()
    incentive = serializers.SerializerMethodField()
    total = serializers.SerializerMethodField()
    month = serializers.SerializerMethodField()

    class Meta:
        model = WalletTransaction

        fields = [
            "id",
            "user_name",
            "user_email",
            "role",
            "salary",
            "incentive",
            "total",
            "month",
            "created_at",
        ]

    def _get_amount(self, obj, transaction_type):
        return (
            WalletTransaction.objects.filter(
                wallet__user=obj.wallet.user,
                transaction_type=transaction_type,
                created_at__year=obj.created_at.year,
                created_at__month=obj.created_at.month,
            ).aggregate(total=Sum("amount"))["total"]
            or 0
        )

    def get_salary(self, obj):
        return obj.amount

    def get_incentive(self, obj):
        return self._get_amount(obj, "INCENTIVE")

    def get_total(self, obj):
        return obj.amount + self.get_incentive(obj)

    def get_month(self, obj):
        return obj.created_at.strftime("%B %Y")