from django.urls import path
from .views import CreateTicketView,TicketListView,TicketDetailView,AcceptTicketView

urlpatterns=[
    path('create/',CreateTicketView.as_view()),
    path('list/',TicketListView.as_view()),
    path('detail/<int:ticket_id>',TicketDetailView.as_view()),
    path('<int:ticket_id>/accept',AcceptTicketView.as_view()),
]