from django.urls import path
from .views import CreateTicketView,TicketListView

urlpatterns=[
    path('create/',CreateTicketView.as_view()),
    path('list/',TicketListView.as_view()),
]