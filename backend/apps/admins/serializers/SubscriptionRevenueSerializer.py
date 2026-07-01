from rest_framework import serializers
from apps.clients.models import ClientSubscription

class SubscriptionRevenueSerializer(serializers.ModelSerializer):

    company = serializers.CharField(
        source="client.company_name",
        read_only=True
    )

    email = serializers.EmailField(
        source="client.user.email",
        read_only=True
    )

    plan = serializers.CharField(
        source="plan.name",
        read_only=True
    )

    amount = serializers.DecimalField(
        source="plan.price",
        max_digits=10,
        decimal_places=2,
        read_only=True
    )
    expires_on = serializers.SerializerMethodField()

    class Meta:
        model = ClientSubscription

        fields = [
            "id",
            "company",
            "email",
            "plan",
            "amount",
            "status",
            "created_at",
            "expires_on",
        ]
    def get_expires_on(self, obj):
        return obj.end_date.strftime("%d %b %Y")