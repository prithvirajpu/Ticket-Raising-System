from rest_framework import status
from apps.tickets.models import Ticket
import requests

def notify_client_service(user, data):
    try:
        ticket_id = data.get("ticket_id")
        subject = data.get("subject")
        message = data.get("message")

        if not ticket_id:
            return {
                "data": None,
                "errors": {"details": "ticket_id is required"},
                "status": status.HTTP_400_BAD_REQUEST
            }

        if not subject:
            return {
                "data": None,
                "errors": {"details": "subject is required"},
                "status": status.HTTP_400_BAD_REQUEST
            }

        if not message:
            return {
                "data": None,
                "errors": {"details": "message is required"},
                "status": status.HTTP_400_BAD_REQUEST
            }

        ticket = (
            Ticket.objects
            .select_related("client", "created_by")
            .filter(id=ticket_id)
            .first()
        )

        if not ticket:
            return {
                "data": None,
                "errors": {"details": "Ticket not found"},
                "status": status.HTTP_404_NOT_FOUND
            }

        client = ticket.client

        if not client:
            return {
                "data": None,
                "errors": {"details": "Client not found"},
                "status": status.HTTP_400_BAD_REQUEST
            }

        if not client.internal_api_key:
            return {
                "data": None,
                "errors": {"details": "Client API Key missing"},
                "status": status.HTTP_400_BAD_REQUEST
            }

        if not client.app_url:
            return {
                "data": None,
                "errors": {"details": "Client App URL missing"},
                "status": status.HTTP_400_BAD_REQUEST
            }
        print(f'clienturl is {client.app_url}')

        NOTIFICATION_ENDPOINT = "/myadmin/api/support/notifications/"

        notification_url = (
            f"{client.app_url.rstrip('/')}{NOTIFICATION_ENDPOINT}"
        )

        headers = {
            "X-API-KEY": client.internal_api_key,
        }

        payload = {
            "email": ticket.created_by.email,
            "subject": subject,
            "message": message,
        }

        response = requests.post(
            notification_url,
            json=payload,
            headers=headers,
            timeout=10,
        )

        try:
            response_data = response.json()
        except Exception:
            response_data = {
                "raw": response.text
            }

        return {
            "data": response_data,
            "errors": None,
            "status": response.status_code
        }

    except Exception as e:
        return {
            "data": None,
            "errors": {
                "details": str(e)
            },
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }