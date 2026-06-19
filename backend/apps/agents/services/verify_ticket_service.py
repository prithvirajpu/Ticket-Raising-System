import requests
from rest_framework import status
from apps.tickets.models import Ticket


def verify_ticket_service(user, data):
    try:
        ticket_id = data.get("ticket_id")

        if not ticket_id:
            return {
                "data": None,
                "errors": {"details": "ticket_id is required"},
                "status": status.HTTP_400_BAD_REQUEST
            }

        # 1. Fetch ticket with client
        ticket = Ticket.objects.select_related("client", "created_by").filter(id=ticket_id).first()

        if not ticket:
            return {
                "data": None,
                "errors": {"details": "Ticket not found"},
                "status": status.HTTP_404_NOT_FOUND
            }

        # 2. Get client directly from ticket
        client = ticket.client

        if not client:
            return {
                "data": None,
                "errors": {"details": "Client not found for ticket"},
                "status": status.HTTP_400_BAD_REQUEST
            }

        # 3. Get client-specific API key
        api_key = client.internal_api_key

        if not api_key:
            return {
                "data": None,
                "errors": {"details": "Client API key missing"},
                "status": status.HTTP_400_BAD_REQUEST
            }

        # 4. Call external verification service
        headers = {
            "X-API-KEY": api_key
        }

        response = requests.post(
            "http://127.0.0.1:8001/api/support/verify/",
            json=data,
            headers=headers,
            timeout=10
        )

        # 5. Return response safely
        try:
            response_data = response.json()
        except Exception:
            response_data = {"raw": response.text}

        return {
            "data": response_data,
            "errors": None,
            "status": response.status_code
        }

    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }