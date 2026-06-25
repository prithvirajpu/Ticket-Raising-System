from django.urls import path
from apps.payments.views import (WalletAPIView,WalletTransactionAPIView,
                                 CreateConnectAccountView,WithdrawalRequestView,
                                 )

urlpatterns = [
    path("wallet/",WalletAPIView.as_view()),
    path("wallet/transactions/",WalletTransactionAPIView.as_view()),
    path("connect-account/",CreateConnectAccountView.as_view()),
    path("withdraw/",WithdrawalRequestView.as_view()),
]