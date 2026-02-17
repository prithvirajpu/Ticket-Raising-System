from django.db import models
from core_app.constants import UserRole, ApprovalStatus
from django.contrib.auth.models import AbstractBaseUser,PermissionsMixin
from .manager import UserManager

class User(AbstractBaseUser,PermissionsMixin):
    objects=UserManager()
    email=models.EmailField(unique=True)
    name=models.CharField(max_length=100)
    phone=models.CharField(max_length=15,default='0000000000')
    business_type=models.CharField(max_length=50,blank=True)
    role=models.CharField(max_length=20,
                          choices=[(i,i)for i in vars(UserRole).values() if isinstance(i,str)],
                          default=UserRole.USER)
    approval_status=models.CharField(max_length=20,
                                    choices=[(i,i) for i in vars(ApprovalStatus).values() if isinstance(i,str)],
                                    default=ApprovalStatus.PENDING)
    is_active=models.BooleanField(default=False)
    is_staff=models.BooleanField(default=False)
    is_verified=models.BooleanField(default=False)
    is_blocked=models.BooleanField(default=False)
    
    created_at=models.DateTimeField(auto_now_add=True)
    profile_completed = models.BooleanField(default=False)

    USERNAME_FIELD='email'
    REQUIRED_FIELDS=['name']

    def __str__(self):
        return self.email
    