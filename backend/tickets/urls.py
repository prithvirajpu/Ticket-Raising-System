from django.urls import path
from .views import (CreateTicketView,TicketListView,TicketDetailView,AcceptTicketView,RejectTicketView,AgentTicketRequestsView,AgentTicketDetailView
                ,AgentOngoingTicketsView,ResolveTicketView )
urlpatterns=[
    #users
    path('create/',CreateTicketView.as_view()),
    path('list/',TicketListView.as_view()),
    path('detail/<int:ticket_id>/',TicketDetailView.as_view()),

    #agents
    path('agents/requests/',AgentTicketRequestsView.as_view()),
    path('agents/in-progress/',AgentOngoingTicketsView.as_view()),
    path('agents/detail/<int:ticket_id>/',AgentTicketDetailView.as_view()),

    path('<int:ticket_id>/accept/',AcceptTicketView.as_view()),
    path('<int:ticket_id>/reject/',RejectTicketView.as_view()),

    path('<int:ticket_id>/resolve/',ResolveTicketView.as_view()),

]