from django.contrib import admin
from django.urls import path,include

urlpatterns = [

    path('admin/', admin.site.urls),
    path('api/auth/', include('apps.accounts.urls')),
    path('api/users/', include('apps.users.urls')),
    path('api/admins/', include('apps.admins.urls')),
    path('api/agents/', include('apps.agents.urls')),
    path('api/clients/', include('apps.clients.urls')),
    path('api/team-leads/', include('apps.teamleads.urls')),
    path('api/managers/', include('apps.managers.urls')),
    path('api/tickets/', include('apps.tickets.urls')),
    path('api/payments/', include('apps.payments.urls')),
    
]
