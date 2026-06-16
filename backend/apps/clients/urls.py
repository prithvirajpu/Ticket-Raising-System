from django.urls import path
from .views import (CurrentSubscriptionAPIView,SubscriptionPlanView,
                    UpdateClientProfileView, UploadDocView,
                    CreateCheckoutSessionAPIView,StripeWebhookAPIView,
                    CancelSubscriptionAPIView)

urlpatterns=[
    path("profile/update/", UpdateClientProfileView.as_view()),
    path('upload/', UploadDocView.as_view()),
    path('subscription/plans/',SubscriptionPlanView.as_view()),
    path('subscription/current/',CurrentSubscriptionAPIView.as_view()),
     #subscription plan checkout 
    path('subscriptions/checkout/',CreateCheckoutSessionAPIView.as_view()),
    path('stripe/webhook/',StripeWebhookAPIView.as_view()),
    path('subscription/cancel/',CancelSubscriptionAPIView.as_view()),
]