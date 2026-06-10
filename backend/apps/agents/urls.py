from django.urls import path
from .views import (UpdateAgentProfileView,    AgentTicketRequestsView,
    AgentOngoingTicketsView,AcceptTicketView,RejectTicketView,
    AgentTicketDetailView,AgentSummaryView,AgentFakeTicketsView,
    AgentFakeTicketDetailView,VerifyTicketAPIView,RetryTrainingAPIView)
import logging
logger=logging.getLogger(__name__)

logger.info("RetryTrainingAPIView =%s", RetryTrainingAPIView)

urlpatterns=[
    path("profile/update/", UpdateAgentProfileView.as_view()),
    
    path('requests/', AgentTicketRequestsView.as_view()),
    path('in-progress/', AgentOngoingTicketsView.as_view()),
    path('details/<int:ticket_id>/', AgentTicketDetailView.as_view()),
    path('training/<int:ticket_id>/retry/',RetryTrainingAPIView.as_view()),

    # actions
    path("<int:ticket_id>/accept/", AcceptTicketView.as_view()),
    path("<int:ticket_id>/reject/", RejectTicketView.as_view()),

    path('summary/', AgentSummaryView.as_view()),

    path('fake-tickets/', AgentFakeTicketsView.as_view()),
    path('fake-tickets/<int:id>/', AgentFakeTicketDetailView.as_view()),
    path('verify/',VerifyTicketAPIView.as_view()),

]