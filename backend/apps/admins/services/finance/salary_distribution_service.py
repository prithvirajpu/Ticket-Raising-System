from rest_framework.pagination import PageNumberPagination
from apps.payments.models import WalletTransaction
from apps.admins.serializers import SalaryDistributionSerializer


def get_salary_distribution(request):

    queryset = (
            WalletTransaction.objects
            .select_related("wallet__user")
            .filter(transaction_type="SALARY")
            .order_by("-created_at")
        )

    paginator = PageNumberPagination()
    paginator.page_size = 5
    paginator.page_query_param = "salary_page"

    page = paginator.paginate_queryset(queryset,request)

    serializer = SalaryDistributionSerializer(page,many=True)

    return {
        "data": serializer.data,

        "pagination": {
            "count": queryset.count(),
            "next": paginator.get_next_link(),
            "previous": paginator.get_previous_link(),
            "page_size": paginator.page_size,
        }
    }