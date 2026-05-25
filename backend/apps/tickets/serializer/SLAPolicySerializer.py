# serializers.py

from rest_framework import serializers
from apps.tickets.models import SLAPolicy

class SLAPolicySerializer(serializers.ModelSerializer):

    plan_name = serializers.CharField(
        source='plan.name',
        read_only=True
    )

    class Meta:
        model = SLAPolicy
        fields = [
            'id',
            'plan',
            'plan_name',
            'priority',
            'resolution_time_minutes',
            'is_active'
        ]