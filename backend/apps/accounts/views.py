from rest_framework.views import APIView
from rest_framework.response import Response
from apps.core_app.utils import return_response
from rest_framework.parsers import MultiPartParser, FormParser
from .services import (verify_otp_service,agent_signup_service,reset_password_service,resend_otp_service,
                       check_user_email_exists,forgot_password_service,client_signup_service,google_client_auth_service,
                       login_service,sso_login_service)
from .serializers import (LoginSerializer,ClientSignupSerializer,
    VerifyOTPSerializer,ForgotPasswordSerializer,ResetPasswordSerializer)
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from rest_framework_simplejwt.views import TokenRefreshView
from apps.core_app.utils import set_refresh_cookie
import logging
logger=logging.getLogger(__name__)

User=get_user_model()

class SSOLoginAPIView(APIView):
    permission_classes = []

    def post(self, request):
        token = request.data.get('token')
        
        result = sso_login_service(request, token)
        if isinstance(result, HttpResponse):
            return result
        print(f'result here : {result}')   

        data = result.get("data",{})
        if not data:
            return HttpResponse(
                """
                <script>
                    window.location.replace("http://localhost:5173/sso-error?code=invalid_login");
                </script>
                """
            )
        sso_loading_url = (
            f"http://localhost:5173/sso-loading"
            f"?access={data['access']}"
            f"&role={data['role']}"
            f"&user_id={data['user_id']}"
            f"&profile_completed={str(data['profile_completed']).lower()}"
            f"&approval_status=APPROVED"
        )

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Redirecting to Dashboard...</title>
        </head>
        <body>
            <h3>Redirecting to dashboard...</h3>
            
            <script>
                window.location.replace("{sso_loading_url}");
            </script>
        </body>
        </html>
        """

        response = HttpResponse(html)
        set_refresh_cookie(response, result["refresh"])

        return response
        
class LoginView(APIView):
    permission_classes=[]

    def post(self,request):
        serializer=LoginSerializer(data=request.data,context={'request':request})
        serializer.is_valid(raise_exception=True)

        user=serializer.validated_data['user']
        result=login_service(user)      
        response= return_response(result)
        set_refresh_cookie(response,result['refresh'])
        return response

class CookieTokenRefreshView(TokenRefreshView):

    def post(self, request, *args, **kwargs):
        print('cookies ',request.COOKIES)
        refresh = request.COOKIES.get("refresh_token")
        print('refresh',refresh)
        if not refresh:
            return Response(
                {"detail": "Refresh token not found."},
                status=401,
            )

        serializer = self.get_serializer(
            data={"refresh": refresh})

        serializer.is_valid(raise_exception=True)

        return Response(serializer.validated_data)

class GoogleClientAuthView(APIView):
    permission_classes = []

    def post(self, request):
        token = request.data.get("id_token")
        role = request.data.get("role")  
        print('helo')
        result=google_client_auth_service(token,role)
        response = return_response(result)
        if result.get("refresh"):
            set_refresh_cookie(response, result["refresh"])
        return response
       
class LogoutView(APIView):
    permission_classes = []

    def post(self, request):
        response = Response({"message": "Logged out"})

        response.delete_cookie("refresh_token")

        return response
    
class AgentSignupView(APIView):
    permission_classes = []
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        result=agent_signup_service(request.data)
        return return_response(result)
    
class ClientSignupView(APIView):
    permission_classes=[]
    
    def post(self,request):
        serializer=ClientSignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result=client_signup_service(serializer)
        return return_response(result)
    
class VerifyOTPView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]
        purpose = serializer.validated_data.get("purpose", "SIGNUP")

        result = verify_otp_service(email, otp, purpose)

        return return_response(result)
    
class ResendOTPView(APIView):
    permission_classes = []

    def post(self, request):
        email = request.data.get('email')
        purpose = request.data.get('purpose')
        
        result=resend_otp_service(email,purpose)
        return return_response(result)
    
class ForgotPasswordView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        result=forgot_password_service(email)
        return return_response(result)
    
class ResetPasswordView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        reset_token=serializer.validated_data['reset_token']
        new_password = serializer.validated_data['new_password']

        result=reset_password_service(reset_token,new_password)
        return return_response(result)
    
class CheckUserExistsView(APIView):
    permission_classes=[]
    
    def post(self,request):
        email=request.data.get('email')
        result=check_user_email_exists(email)

        return return_response(result)
    