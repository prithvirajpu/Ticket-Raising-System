import stripe
from rest_framework import status
from django.conf import settings

stripe.api_key = settings.STRIPE_SECRET_KEY

def create_stripe_connect_account_service(user):
    if user.stripe_connect_account_id:
        account_id=user.stripe_connect_account_id
    else:
        account= create_connect_account(user)
        account_id=account.id
    onboarding_url = create_onboarding_link(user)
    return {
        'data':{'onboarding_url':onboarding_url},
        'errors':{},
        'status':status.HTTP_200_OK
        }

def create_connect_account(user):
    account = stripe.Account.create(
        type="express",
        country="US",
        email=user.email,
    )

    user.stripe_connect_account_id = account.id
    user.save(update_fields=["stripe_connect_account_id"])

    return account

def create_onboarding_link(user):
    account_link = stripe.AccountLink.create(
        account=user.stripe_connect_account_id,
        refresh_url="http://localhost:5173/wallet",
        return_url="http://localhost:5173/connect-success",
        type="account_onboarding",
    )

    return account_link.url