from rest_framework import serializers
from apps.payments.models import SalaryDistributionConfig


class SalaryDistributionConfigSerializer(serializers.ModelSerializer):

    class Meta:
        model = SalaryDistributionConfig
        fields = [
            "id",
            "agent_percentage",
            "incentive_percentage",
            "team_lead_percentage",
            "manager_percentage",
            "is_active",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
        ]