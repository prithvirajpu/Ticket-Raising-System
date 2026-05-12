from rest_framework import status

def get_profile_service(user):
    try:
        data={'id':user.id,
              'name':user.name,
              'email':user.email,
              'phone':user.phone,
              'role':user.role}
        return {
            'data':{'message':data},
            'errors':{},
            'status':status.HTTP_200_OK
        }
    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": status.HTTP_400_BAD_REQUEST
        }

def update_profile_service(user,data):
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