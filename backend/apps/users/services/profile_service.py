from rest_framework import status
from django.db import transaction
from django.core.cache import cache
import logging
logger=logging.getLogger(__name__)

def get_profile_service(user):
    cache_key = f"profile_page_{user.id}"
    cached_data = cache.get(cache_key)

    if cached_data:
        logger.warning('profile from redis')
        return cached_data
    logger.warning('profile from db')
    try:
        data={'id':user.id,
              'name':user.name,
              'email':user.email,
              'phone':user.phone,
              'role':user.role}
        result= {
            'data':{'message':data},
            'errors':{},
            'status':status.HTTP_200_OK
        }
        cache.set(cache_key, result, timeout=60)
        return result
    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": status.HTTP_400_BAD_REQUEST
        }

def update_profile_service(user,data):
    with transaction.atomic():
        try:
            user.name=data.get('name',user.name)
            user.phone=data.get('phone',user.phone)

            user.save(update_fields=['name','phone'])
            return {
                "data": {"message": "Profile updated successfully"},
                "errors": {},
                "status": status.HTTP_200_OK
            }
        except Exception as e:
            return {
                "data": None,
                "errors": {"details": str(e)},
                "status": status.HTTP_400_BAD_REQUEST
            }