from django.urls import path
from .views import (LoginView,PendingUsersView,ApproveUserView,RejectUserView,AgentSignupView,ClientSignupView,
                    VerifyOTPView,ResendOTPView,ForgotPasswordView,ResetPasswordView,AgentApplicationDetailView,
                    GoogleClientAuthView,UpdateClientProfileView,UpdateAgentProfileView,ClientListView,AgentListView)

urlpatterns=[
    path('login/',LoginView.as_view()),
    path('signup/agent/',AgentSignupView.as_view()),
    path('signup/client/',ClientSignupView.as_view()),
    path("google/", GoogleClientAuthView.as_view(), name="google-client-login"),
    path('verify-otp/',VerifyOTPView.as_view()),
    path('resend-otp/',ResendOTPView.as_view()),
    path('forgot-password/',ForgotPasswordView.as_view()),
    path('reset-password/',ResetPasswordView.as_view()),

    path('admin/pending-users/',PendingUsersView.as_view()),
    path('admin/agent/<int:pk>/',AgentApplicationDetailView.as_view()),
    path('admin/approve/<int:pk>/',ApproveUserView.as_view()),
    path('admin/reject/<int:pk>/',RejectUserView.as_view()),
    path("admin/clients/", ClientListView.as_view(), name="admin-clients"),
    path("admin/agents/", AgentListView.as_view(), name="admin-agents"),

    path("client/profile/update/", UpdateClientProfileView.as_view()),
    path("agent/profile/update/", UpdateAgentProfileView.as_view()),

]