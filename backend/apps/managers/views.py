from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from apps.core_app.utils import return_response
from .services import (get_manager_tickets_service,get_clients_with_documents,get_client_documents,summarize_document_service,submit_summary_service,
                       )

# Create your views here.

class ManagerTicketsView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        result=get_manager_tickets_service(request.user)
        return return_response(result)
    
class ClientListWithDocsView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        result=get_clients_with_documents()
        return return_response(result)
    
class ClientDocumentsView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request,client_id):
        result= get_client_documents(client_id)
        return return_response(result)
    
class SummarizeDocumentView(APIView):
    permission_classes= [IsAuthenticated]

    def post (self,request,doc_id):
        result= summarize_document_service(request.user,doc_id)
        return return_response(result)
    
class SubmitSummaryView(APIView):
    permission_classes=[IsAuthenticated]

    def post (self,request,doc_id):
        result= submit_summary_service(request,doc_id)
        return return_response(result)
    
