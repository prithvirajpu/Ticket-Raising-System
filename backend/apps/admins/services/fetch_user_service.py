from rest_framework import status
from rest_framework.pagination import PageNumberPagination

from apps.accounts.models import User

from ..serializers import UserManagementSerializer

import logging
logger=logging.getLogger(__name__)

def fetch_users_service(request):

    try:

        users = User.objects.filter(
            role='USER'
        ).order_by('-id')

        paginator = PageNumberPagination()

        paginator.page_size = 5

        page = paginator.paginate_queryset(
            users,
            request
        )

        serializer = UserManagementSerializer(
            page,
            many=True
        )
        logger.info('user data %s',serializer.data)

        total_users = users.count()

        active_users = users.filter(
            is_active=True
        ).count()

        inactive_users = users.filter(
            is_active=False
        ).count()

        next_link = (
            paginator.get_next_link()
            if hasattr(paginator, "page")
            else None
        )

        previous_link = (
            paginator.get_previous_link()
            if hasattr(paginator, "page")
            else None
        )

        return {

            "paginator": {

                "count": users.count(),

                "next": next_link,

                "previous": previous_link,

                "page_size": paginator.page_size,
            },

            "data": {

                "message": {

                    "users": serializer.data,

                    "total_users": total_users,

                    "active_users": active_users,

                    "inactive_users": inactive_users
                }
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