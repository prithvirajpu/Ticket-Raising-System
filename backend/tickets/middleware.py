import jwt
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth import get_user_model
from urllib.parse import parse_qs
from asgiref.sync import sync_to_async

User = get_user_model()


class JWTAuthMiddleware:
    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):   # ✅ IMPORTANT
        query_string = scope.get("query_string", b"").decode()
        query_params = parse_qs(query_string)

        token = query_params.get("token")
        token = token[0] if token else None

        scope["user"] = await self.get_user(token)

        return await self.inner(scope, receive, send)

    @sync_to_async
    def get_user(self, token):
        if not token:
            return AnonymousUser()

        try:
            decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = decoded.get("user_id")
            return User.objects.get(id=user_id)
        except Exception:
            return AnonymousUser()