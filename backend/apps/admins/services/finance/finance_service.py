from rest_framework import status

from .finance_summary_service import get_finance_summary
from .salary_distribution_service import get_salary_distribution
from .subscription_revenue_service import get_subscription_revenue

def admin_finance_service(request):
    
    return {
        "data": {
            "summary": get_finance_summary(),
            "salary": get_salary_distribution(request),
            "subscriptions": get_subscription_revenue(request),
        },
        "errors": {},
        "status": status.HTTP_200_OK,
    }