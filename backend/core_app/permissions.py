from rest_framework.permissions import BasePermission
from .constants import UserRole

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        print('user is ',request.user)
        return (
            request.user.is_authenticated and request.user.is_active and request.user.role==UserRole.ADMIN
        )
    