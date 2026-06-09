from django.urls import path
from .views import (
    SendMessageView,ResolveTicketView,NotificationListView,
    TicketMessageView,DashboardView,EscalatedTicketView,

    MarkAllNotificationsReadView,TrainingMessagesAPIView,
    MarkNotificationReadView

)

urlpatterns = [
    # chat
    path('dashboard/',DashboardView.as_view()),
    path('<int:ticket_id>/send-message/', SendMessageView.as_view()),
    path('<int:ticket_id>/messages/', TicketMessageView.as_view()),
    #training tickets
    path('training-tickets/<int:ticket_id>/messages/', TrainingMessagesAPIView.as_view()),

    path("<int:ticket_id>/resolve/", ResolveTicketView.as_view()),
    path("<int:ticket_id>/escalate/", EscalatedTicketView.as_view()),

    path('notifications/',NotificationListView.as_view()),
    path('notifications/<int:notification_id>/read/',MarkNotificationReadView.as_view()),
    path('notifications/mark-all-read/',MarkAllNotificationsReadView.as_view()),
]