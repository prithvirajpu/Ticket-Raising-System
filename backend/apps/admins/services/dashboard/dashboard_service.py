from rest_framework import status
from .dashboard_ticket_service import get_ticket_dashboard
from .dashboard_user_service import get_user_dashboard
from .dashboard_report_service import get_ticket_report_dashboard
from .dashboard_wallet_service import get_wallet_dashboard

def admin_dashboard_service(request):
    period=request.GET.get('period','7d')
    return {
        'data':{
            'tickets':get_ticket_dashboard(period),
            'wallet':get_wallet_dashboard(period),
            'users':get_user_dashboard(),
            'reports':get_ticket_report_dashboard(period),
        },
        'errors':{},
        'status':status.HTTP_200_OK
    }