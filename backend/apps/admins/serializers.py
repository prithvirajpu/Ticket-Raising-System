from rest_framework import serializers
from apps.core_app.models import AgentApplication
import logging

logger=logging.getLogger(__name__)


class UserApprovalSerializer(serializers.ModelSerializer):
    class Meta:
        model=AgentApplication
        fields = ['id', 'email', 'phone', 'status','full_name','applied_at']
