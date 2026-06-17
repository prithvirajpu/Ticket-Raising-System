from django.urls import path
from apps.payments.views import (WalletAPIView,WalletTransactionAPIView)

urlpatterns = [
    path("wallet/",WalletAPIView.as_view()),
    path("wallet/transactions/",WalletTransactionAPIView.as_view()),
]