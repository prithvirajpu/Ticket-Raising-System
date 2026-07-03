from django.db import transaction
from apps.accounts.models import User
from django.utils import timezone


def finalize_training(user_id):

    with transaction.atomic():

        user = User.objects.get(id=user_id)

        user.is_certified_agent = True
        user.certified_at = timezone.now()

        user.save(
            update_fields=[
                "is_certified_agent",'certified_at'
            ]
        )