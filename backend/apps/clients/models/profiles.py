from django.db import models
from django.contrib.auth import get_user_model
import secrets
User=get_user_model()

class ClientProfile(models.Model):
    user=models.OneToOneField(User,on_delete=models.CASCADE,related_name='client_profile')
    company_name=models.CharField(max_length=255)
    billing_email=models.EmailField()

    stripe_customer_id = models.CharField(max_length=255,null=True,blank=True)

    team_lead=models.ForeignKey(User,on_delete=models.SET_NULL,null=True,blank=True,related_name='clients')
    manager = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='clients_as_manager')

    sso_shared_secret= models.CharField(max_length=128,unique=True,null=True,blank=True)
    internal_api_key=models.CharField(max_length=128,unique=True,null=True,blank=True)
    app_url = models.URLField()

    created_at=models.DateTimeField(auto_now_add=True)

    def save(self,*args,**kwargs):
        if not self.sso_shared_secret:
            self.sso_shared_secret=(
                'trs_sso_'+secrets.token_urlsafe(32)
            )
        if not self.internal_api_key:
            self.internal_api_key=(
                'trs_live_'+secrets.token_urlsafe(32)
            )
        super().save(*args,**kwargs)

    def __str__(self):
        return self.company_name
    