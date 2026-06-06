import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter,URLRouter
from django.urls import path,re_path

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django_asgi_app = get_asgi_application()

from apps.tickets.consumer import ChatConsumer,CallConsumer,NotificationConsumer
from apps.tickets.middleware import JWTAuthMiddleware


application = ProtocolTypeRouter({
    "http": django_asgi_app,

    "websocket": JWTAuthMiddleware(
        URLRouter([
            re_path(r"ws/chat/(?P<ticket_id>\d+)/$", ChatConsumer.as_asgi()),
            re_path(r"ws/call/$",CallConsumer.as_asgi()),
            re_path(r"ws/notifications/$",NotificationConsumer.as_asgi()),
        ])
    ),
})