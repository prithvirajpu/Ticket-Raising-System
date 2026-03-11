from django.db import models
from django.contrib.auth import get_user_model
User=get_user_model()

class ClientProfile(models.Model):
    user=models.OneToOneField(User,on_delete=models.CASCADE,related_name='client_profile')
    company_name=models.CharField(max_length=255)
    billing_email=models.EmailField()
    created_at=models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.company_name