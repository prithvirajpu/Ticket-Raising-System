from celery import shared_task
from django.contrib.auth import get_user_model

from apps.accounts.services import EmailService

User = get_user_model()


@shared_task(bind=True, max_retries=3)
def send_welcome_email_task(self, user_id):
    try:
        user = User.objects.get(id=user_id)

        EmailService.send_welcome_email(user)

    except User.DoesNotExist:
        return

    except Exception as exc:
        raise self.retry(exc=exc, countdown=60)