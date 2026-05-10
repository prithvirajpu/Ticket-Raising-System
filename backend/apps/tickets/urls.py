from django.urls import path
from .views import (
    SendMessageView,ResolveTicketView,
    TicketMessageView,DashboardView,EscalatedTicketView
)

urlpatterns = [
    # chat
    path('dashboard/',DashboardView.as_view()),
    path('<int:ticket_id>/send-message/', SendMessageView.as_view()),
    path('<int:ticket_id>/messages/', TicketMessageView.as_view()),

    path("<int:ticket_id>/resolve/", ResolveTicketView.as_view()),
    path("<int:ticket_id>/escalate/", EscalatedTicketView.as_view()),
]