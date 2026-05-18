import requests
from django.conf import settings

def verify_ticket_service(data):
    try:
        headers = {
            "X-API-KEY": settings.INTERNAL_API_KEY
        }

        response = requests.post(
            "http://127.0.0.1:8001/api/support/verify/",
            json=data,
            headers=headers
        )

        return {
            "data": response.json(),
            "errors": None,
            "status": response.status_code
        }

    except Exception as e:

        return {
            "data": None,
            "errors": {
                "details": str(e)
            },
            "status": 500
        }