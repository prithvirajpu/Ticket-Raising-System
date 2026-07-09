from django.urls import path
from .views import (GenerateFakeTicketView,TeamLeadTicketView,
                    TeamLeadSummaryView,SummaryTeamLeadView,
                    SubmitSummaryToAgentsView,TLDashboardView)


urlpatterns=[
    path('dashboard/',TLDashboardView.as_view()),
    path('assigned-tickets/',TeamLeadTicketView.as_view()),
    path('summaries/',TeamLeadSummaryView.as_view()),
    path('generate-agent-summary/<int:summary_id>/',SummaryTeamLeadView.as_view()),
    path('submit-summary/<int:summary_id>/',SubmitSummaryToAgentsView.as_view()),
    path('generate-fake-tickets/',GenerateFakeTicketView.as_view()),

]