from django.urls import path
from .views import LoginView,PendingUsersView,ApproveUserView,RejectUserView,AgentSignupView,ClientSignupView

urlpatterns=[
    path('login/',LoginView.as_view()),
    path('signup/agent/',AgentSignupView.as_view()),
    path('admin/pending-users/',PendingUsersView.as_view()),
    path('admin/approve/<int:pk>/',ApproveUserView.as_view()),
    path('admin/reject/<int:pk>/',RejectUserView.as_view()),
]