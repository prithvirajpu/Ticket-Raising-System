from django.urls import path
from .views import (HandleDemoPaymentView,SubscriptionPlanView,UpdateClientProfileView, UploadDocView)

urlpatterns=[
    path("profile/update/", UpdateClientProfileView.as_view()),
    path('upload/', UploadDocView.as_view()),
    path('subscription/plans/',SubscriptionPlanView.as_view()),
    path('subscription/demo-payment/',HandleDemoPaymentView.as_view()),
]