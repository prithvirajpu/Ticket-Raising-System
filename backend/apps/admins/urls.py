from django.urls import path
from .views import (UserManagementView,SLARulesView,PendingUsersView,AgentApplicationDetailView,ApproveUserView,RejectUserView,
                    ClientListView,AgentListView,ToggleAgentStatusView,AssignHierarchyView,AllUsersView,HierarchyView,
                    WithdrawRequestView,ApproveWithdrawalView,RejectWithdrawalView,AdminWalletTransactionAPIView,
                    AdminDashboardAPIView,)

urlpatterns=[
    path('dashboard/',AdminDashboardAPIView.as_view()),
    path('pending-users/',PendingUsersView.as_view()),
    path('agent/<int:pk>/',AgentApplicationDetailView.as_view()),
    path('approve/<int:pk>/',ApproveUserView.as_view()),
    path('reject/<int:pk>/',RejectUserView.as_view()),
    path("clients/", ClientListView.as_view()),
    path("agents/", AgentListView.as_view()),
    path('agents/<int:agent_id>/status/',ToggleAgentStatusView.as_view()),
    path('sla-rules/',SLARulesView.as_view()),
    path('users/',UserManagementView.as_view()),
    path("assign-hierarchy/", AssignHierarchyView.as_view()),
    path("users/all/", AllUsersView.as_view()),
    path("hierarchy/", HierarchyView.as_view()),
    path("wallet-transactions/", AdminWalletTransactionAPIView.as_view()),
    path("wallet/requests/", WithdrawRequestView.as_view()),
    path("wallet/requests/<int:pk>/approve/",ApproveWithdrawalView.as_view()),
    path("wallet/requests/<int:pk>/reject/",RejectWithdrawalView.as_view()),

]