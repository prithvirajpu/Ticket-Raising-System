from django.urls import path
from .views import (ManagerTicketsView,ClientListWithDocsView,ClientDocumentsView,SummarizeDocumentView,SubmitSummaryView)


urlpatterns=[
    path('tickets/', ManagerTicketsView.as_view()),
    path('clients-docs/', ClientListWithDocsView.as_view()),
    path('clients-docs/<int:client_id>/', ClientDocumentsView.as_view()),
    path('summarize/<int:doc_id>/',SummarizeDocumentView.as_view()),
    path('submit-summary/<int:doc_id>/',SubmitSummaryView.as_view()),
]