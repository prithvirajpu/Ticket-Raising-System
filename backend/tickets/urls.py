from django.urls import path
from .views import CreateTicketView

urlpatterns=[
    path('create/',CreateTicketView.as_view()),
]