from apps.tickets.models import DocumentSummary
from rest_framework import status

def agent_summary_service(request):
    user=request.user
    summary= DocumentSummary.objects.filter(assigned_to=user).first()
    if not summary:
        return {
            "data": None,
            "errors":{'details':"No summary found"},
            'status':status.HTTP_200_OK
            }
    return {
        'data':{'id':summary.id,
            'summary':summary.summary},
        'errors':None,
        'status':status.HTTP_200_OK
    }
