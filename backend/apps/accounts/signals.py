
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User
from apps.payments.models import Wallet

@receiver(post_save, sender=User)
def create_wallet(sender, instance, created, **kwargs):
    if created and instance.role in ['AGENT','TEAM_LEAD','MANAGER']:
        Wallet.objects.get_or_create(user=instance)
