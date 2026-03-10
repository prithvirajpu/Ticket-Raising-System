from django.urls import path
from .views import CreateTicketView,TicketListView,TicketDetailView

urlpatterns=[
    path('create/',CreateTicketView.as_view()),
    path('list/',TicketListView.as_view()),
    path('detail/<int:ticket_id>',TicketDetailView.as_view()),
]