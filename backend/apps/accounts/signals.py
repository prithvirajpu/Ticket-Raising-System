
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User
from apps.payments.models import Wallet
from apps.accounts.tasks import send_welcome_email_task

@receiver(post_save, sender=User)
def create_wallet(sender, instance, created, **kwargs):
    if created and instance.role in ['AGENT','TEAM_LEAD','MANAGER','ADMIN']:
        Wallet.objects.get_or_create(user=instance)

@receiver(post_save,sender=User)
def user_created_signal(sender,instance,created,**kwargs):
    if not created:
        return 
    if instance.role!= 'USER':
        return 
    send_welcome_email_task.delay(instance.id)