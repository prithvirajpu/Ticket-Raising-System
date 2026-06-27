from apps.tickets.models import Notification
from ..serializer import NotificationSerializer
from rest_framework import status
from django.db import transaction
from django.core.cache import cache

import logging
logger= logging.getLogger(__name__)

def notification_service(request):
    cache_key = f"notification_{request.user.id}"
    cached_data = cache.get(cache_key)

    if cached_data:
        return cached_data
    
    notifications=Notification.objects.filter(
        user=request.user
    ).order_by('-created_at')
    serializer= NotificationSerializer(notifications,many=True)
    unread_count= notifications.filter(is_read=False).count()
    logger.info('the notification serializer data %s',serializer.data)
    result= {
        'data':{'serializer':serializer.data,'unread_count':unread_count},
        'errors':{},
        'status':status.HTTP_200_OK
    } 
    cache.set(cache_key, result, timeout=60)
    return result

def mark_as_read_notification(request,notification_id):
    with transaction.atomic():
        notification=Notification.objects.get(
            id=notification_id,
            user=request.user
        )
        notification.is_read=True
        notification.save(update_fields=['is_read'])
        return {
            'data':{'message':'Notification marked as read'},
            'errors':{},
            'status':status.HTTP_200_OK
        }
    
def mark_all_notifications_read_service(request):
    Notification.objects.filter(
        user=request.user,
        is_read=False
    ).update(is_read=True)

    return {
        "data": {"message": "All notifications marked as read"},
        "errors": {},
        "status": status.HTTP_200_OK
    }