from django.urls import path
from .views import (UpdateClientProfileView, UploadDocView)

urlpatterns=[
    path("profile/update/", UpdateClientProfileView.as_view()),
    path('upload/', UploadDocView.as_view()),
]