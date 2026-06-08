from rest_framework import serializers
from apps.core_app.models import AgentApplication
from apps.accounts.models import User

import logging

logger=logging.getLogger(__name__)


class UserApprovalSerializer(serializers.ModelSerializer):
    class Meta:
        model=AgentApplication
        fields = ['id', 'email', 'phone', 'status','full_name','applied_at']

class UserManagementSerializer(serializers.ModelSerializer):
    client_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id',
            'name',
            'email',
            'phone',
            'is_active',
            'client_name'
        ]
    def get_client_name(self,obj):
        try:
            return obj.client_user.client_profile.company_name
        except:
            return None

class AssignHierarchySerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    manager_id = serializers.IntegerField(required=False, allow_null=True)
    team_lead_id = serializers.IntegerField(required=False, allow_null=True)