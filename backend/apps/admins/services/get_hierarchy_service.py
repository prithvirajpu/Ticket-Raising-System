from rest_framework import status

from apps.accounts.models import User
from apps.clients.models import ClientProfile
from apps.users.models import ClientUser
from apps.core_app.constants import UserRole
import logging
logger=logging.getLogger(__name__)

def get_hierarchy_service():

    try:
        client = ClientProfile.objects.select_related(
            "manager",
            "team_lead"
        ).first()

        if not client:

            return {
                "data": {},
                "errors": {
                    "details": "No client found"
                },
                "status": status.HTTP_404_NOT_FOUND
            }
        logger.info('manager=%s and team lead= %s',client.manager,client.team_lead)

        agents = User.objects.filter(
            role=UserRole.AGENT,
            manager=client.manager,
            team_lead=client.team_lead
        )

        return {
            "data": {
                "client": {
                    "id": client.id,
                    "company_name": client.company_name
                },

                "manager": {
                    "id": client.manager.id,
                    "name": client.manager.name,
                    "email": client.manager.email
                } if client.manager else None,

                "team_lead": {
                    "id": client.team_lead.id,
                    "name": client.team_lead.name,
                    "email": client.team_lead.email
                } if client.team_lead else None,

                "agents": [
                    {
                        "id": agent.id,
                        "name": agent.name,
                        "email": agent.email
                    }
                    for agent in agents
                ],
            },

            "errors": {},

            "status": status.HTTP_200_OK
        }

    except Exception as e:

        return {
            "data": {},
            "errors": {
                "details": str(e)
            },
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }