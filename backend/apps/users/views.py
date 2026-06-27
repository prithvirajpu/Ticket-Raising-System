from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from apps.core_app.utils import return_response
from ..tickets.serializer import TicketSerializer
from .services import (create_ticket_service,get_ticket_list_service,get_ticket_detail_service,
                       close_ticket_service,get_profile_service,update_profile_service,
                       submit_review_service,reopen_ticket_service,timeline_service,
                       user_dashboard)

import logging
logger= logging.getLogger(__name__)

class CreateTicketView(APIView):
    permission_classes=[IsAuthenticated]

    def post(self,request):
        logger.info("REQUEST USER ID :%s", request.user.id)
        logger.info("REQUEST USER EMAIL :%s", request.user.email)
        serializer=TicketSerializer(data=request.data)
        if not serializer.is_valid():
            logger.info('validated errors %s', serializer.errors)
            return Response({
                "data":None,
                "errors":serializer.errors,
                "status":400
            })
        logger.info('validated data %s',serializer.validated_data)
        result=create_ticket_service(serializer.validated_data,request.user)

        return return_response(result)
    
class TicketListView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        search=request.query_params.get('search','')
        sort=request.query_params.get('sort','newest')
        page = int(request.query_params.get('page', 1))
        result=get_ticket_list_service(request,sort,search,page)
        return return_response(result)
    
class TicketDetailView(APIView):
    permission_classes=[IsAuthenticated]
    def get(self,request,ticket_id):
        result=get_ticket_detail_service(ticket_id,request)
        return return_response(result)
    
class TicketCloseView(APIView):
    permission_classes=[IsAuthenticated]
    def post(self,request,ticket_id):
        res=close_ticket_service(request.user,ticket_id)
        return return_response(res)
    
class SubmitReviewView(APIView):
    permission_classes=[IsAuthenticated]
    def post(self,request,ticket_id):
        rating=request.data.get('rating')
        review=request.data.get('review','')
        res=submit_review_service(request.user,ticket_id,rating,review)
        return return_response(res)
    
class UserProfileView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        result=get_profile_service(request.user)
        return return_response(result)
    
class UpdateProfileView(APIView):
    permission_classes= [IsAuthenticated]

    def put(self,request):
        result= update_profile_service(request.user,request.data)
        return return_response(result)
    
class ReopenTicketView(APIView):
    permission_classes=[IsAuthenticated]

    def patch(self,request,ticket_id):
        result=reopen_ticket_service(request.user,ticket_id)
        return return_response(result)
    
class TicketTimelineView(APIView):
    permission_classes =[IsAuthenticated]

    def get(self,request,ticket_id):
        result=timeline_service(ticket_id)
        return return_response(result)
    
class UserDashboardView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        result=user_dashboard(request.user)
        return return_response(result)