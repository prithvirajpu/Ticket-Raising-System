from rest_framework import status
from django.contrib.auth import get_user_model
User=get_user_model()

def check_user_email_exists(email):
    if email and User.objects.filter(email=email).exists():
        return {'success':False,
                'errors':{''
                'email':'Email already exists'}}
    return {'success':True,'message':'available','status':status.HTTP_200_OK}