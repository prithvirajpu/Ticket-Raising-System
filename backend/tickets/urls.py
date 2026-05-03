from django.urls import path
from .views import (CreateTicketView,TicketListView,TicketDetailView,AcceptTicketView,RejectTicketView,AgentTicketRequestsView,AgentTicketDetailView
                ,AgentOngoingTicketsView,ResolveTicketView,TicketCloseView,SubmitReviewView,EscalatedTicketView,UserProfileView,UpdateProfileView,
                 TeamLeadTicketView,ManagerTicketsView,UploadDocView,ClientListWithDocsView,ClientDocumentsView,SummarizeDocumentView,SubmitSummaryView,
                  TeamLeadSummaryView,SummaryTeamLeadView,SubmitSummaryToAgentsView,AgentSummaryView,DashboardView,GenerateFakeTicketView,AgentFakeTicketsView,AgentFakeTicketDetailView )
urlpatterns=[

    #users
    path('create/',CreateTicketView.as_view()),
    path('list/',TicketListView.as_view()),
    path('details/<int:ticket_id>/',TicketDetailView.as_view()),
    path('<int:ticket_id>/close/',TicketCloseView.as_view()),
    path('<int:ticket_id>/review/',SubmitReviewView.as_view()),
    path('user/profile/',UserProfileView.as_view()),
    path('user/profile/update/',UpdateProfileView.as_view()),

    #agents
    path('agents/requests/',AgentTicketRequestsView.as_view()),
    path('agents/in-progress/',AgentOngoingTicketsView.as_view()),
    path('agents/detail/<int:ticket_id>/',AgentTicketDetailView.as_view()),
    path('<int:ticket_id>/escalate/',EscalatedTicketView.as_view()),

    path('<int:ticket_id>/accept/',AcceptTicketView.as_view()),
    path('<int:ticket_id>/reject/',RejectTicketView.as_view()),

    path('<int:ticket_id>/resolve/',ResolveTicketView.as_view()),
    path('agent/summary/',AgentSummaryView.as_view()),
    path('agent/fake-tickets/',AgentFakeTicketsView.as_view()),
    path('agent/fake-tickets/<int:id>/',AgentFakeTicketDetailView.as_view()),

    #Team lead
    path('team-lead/assigned-tickets/',TeamLeadTicketView.as_view()),
    path('team-lead/summaries/',TeamLeadSummaryView.as_view()),
    path('team-lead/generate-agent-summary/<int:summary_id>/',SummaryTeamLeadView.as_view()),
    path('team-lead/submit-summary/<int:summary_id>/',SubmitSummaryToAgentsView.as_view()),

    #Manager
    path('manager/tickets/', ManagerTicketsView.as_view()),
    path('manager/clients-docs/', ClientListWithDocsView.as_view()),
    path('manager/clients-docs/<int:client_id>/', ClientDocumentsView.as_view()),
    path('manager/summarize/<int:doc_id>/',SummarizeDocumentView.as_view()),
    path('manager/submit-summary/<int:doc_id>/',SubmitSummaryView.as_view()),
    path('generate-fake-tickets/',GenerateFakeTicketView.as_view()),

    #Client
    path('client/upload/',UploadDocView.as_view()),

    #Dashboard
    path('dashboard/',DashboardView.as_view()),
]