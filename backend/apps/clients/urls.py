from django.urls import path
from .views import (CurrentSubscriptionAPIView,SubscriptionPlanView,
                    UpdateClientProfileView, UploadDocView,
                    CreateCheckoutSessionAPIView,StripeWebhookAPIView,
                    CancelSubscriptionAPIView,ClientIntegrationKeysAPIView,
                    RegenerateClientKeysAPIView,ClientDashboardAPIView)

urlpatterns=[
    path("profile/update/", UpdateClientProfileView.as_view()),
    path('upload/', UploadDocView.as_view()),
    path('subscription/plans/',SubscriptionPlanView.as_view()),
    path('subscription/current/',CurrentSubscriptionAPIView.as_view()),
    path('integration-keys/',ClientIntegrationKeysAPIView.as_view()),
    path("integration/keys/regenerate/", RegenerateClientKeysAPIView.as_view()),
     #subscription plan checkout 
    path('subscriptions/checkout/',CreateCheckoutSessionAPIView.as_view()),
    path('stripe/webhook/',StripeWebhookAPIView.as_view()),
    path('subscription/cancel/',CancelSubscriptionAPIView.as_view()),
    path('dashboard/',ClientDashboardAPIView.as_view()),

]