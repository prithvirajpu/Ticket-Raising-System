from django.urls import path
from .views import (
    CreateTicketView,
    TicketListView,
    TicketDetailView,
    TicketCloseView,
    SubmitReviewView,
    UserProfileView,TicketTimelineView,
    UpdateProfileView,ReopenTicketView
)

urlpatterns = [
    # tickets
    path("tickets/create/", CreateTicketView.as_view()),
    path("tickets/list/", TicketListView.as_view()),
    path("details/<int:ticket_id>/", TicketDetailView.as_view()),

    path("tickets/<int:ticket_id>/close/", TicketCloseView.as_view()),
    path("tickets/<int:ticket_id>/review/", SubmitReviewView.as_view()),
    path('<int:ticket_id>/reopen/', ReopenTicketView.as_view()),
    path('<int:ticket_id>/timeline/', TicketTimelineView.as_view()),

    # profile
    path("profile/", UserProfileView.as_view()),
    path("profile/update/", UpdateProfileView.as_view()),
]