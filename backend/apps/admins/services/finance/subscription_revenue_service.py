from rest_framework.pagination import PageNumberPagination

from apps.clients.models import ClientSubscription

from apps.admins.serializers.SubscriptionRevenueSerializer import SubscriptionRevenueSerializer


def get_subscription_revenue(request):

    queryset = (
        ClientSubscription.objects
        .select_related(
            "client",
            "client__user",
            "plan"
        )
        .order_by("-created_at")
    )

    paginator = PageNumberPagination()
    paginator.page_size = 5
    paginator.page_query_param = "subscription_page"

    page = paginator.paginate_queryset(queryset,request)

    serializer = SubscriptionRevenueSerializer(
        page,
        many=True
    )

    return {
        "data": serializer.data,

        "pagination": {
            "count": queryset.count(),
            "next": paginator.get_next_link(),
            "previous": paginator.get_previous_link(),
            "page_size": paginator.page_size,
        }
    }