from django.db import transaction
from apps.accounts.models import User


def finalize_training(user_id):

    with transaction.atomic():

        user = User.objects.get(id=user_id)

        user.is_certified_agent = True

        user.save(
            update_fields=[
                "is_certified_agent",
            ]
        )