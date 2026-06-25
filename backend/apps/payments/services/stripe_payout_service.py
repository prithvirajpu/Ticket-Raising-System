import stripe
from django.conf import settings
from django.contrib.auth import get_user_model
import logging

logger= logging.getLogger()
User=get_user_model()

stripe.api_key= settings.STRIPE_SECRET_KEY

def send_stripe_transfer(user,amount):
    if not user.stripe_connect_account_id:
        raise Exception(

            'Agent has not connected Stripe account'
        )
    transfer= stripe.Transfer.create(
        amount=int(amount * 100),
        currency='usd',
        destination=user.stripe_connect_account_id,
        )
    return transfer
