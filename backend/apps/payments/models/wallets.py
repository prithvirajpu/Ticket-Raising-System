from django.db import models
from django.contrib.auth import  get_user_model
User=get_user_model()

class Wallet(models.Model):
    user= models.OneToOneField(User,on_delete=models.CASCADE)
    balance= models.DecimalField(max_digits=12,decimal_places=2,default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email} Wallet"

class WalletTransaction(models.Model):
    TRANSACTION_TYPES=[
        ('SALARY', 'Salary'),
        ('INCENTIVE','Incentive'),
        ('BONUS','Bonus'),
        ('WITHDRAWAL','Withdrawal'),
        ('ADJUSTMENT','Adjustment'),
    ]
    wallet= models.ForeignKey(Wallet,on_delete=models.CASCADE,related_name='transactions')
    transaction_type= models.CharField(choices=TRANSACTION_TYPES,max_length=30)
    created_by = models.ForeignKey(User,on_delete=models.SET_NULL,null=True,blank=True,related_name='wallet_transactions_created')
    
    amount=models.DecimalField(max_digits=12,decimal_places=2)
    description=models.TextField(blank=True)
    
    created_at= models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.wallet.user.email} - {self.transaction_type}"
    
class WithdrawalRequest(models.Model):
    STATUS_CHOICES = [
        ("PENDING","Pending"),
        ("APPROVED","Approved"),
        ("REJECTED","Rejected"),
        ("PAID","Paid"),
    ]
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    amount=models.DecimalField(max_digits=12,decimal_places=2)
    status= models.CharField(choices=STATUS_CHOICES,max_length=20,default='PENDING')
    remarks = models.TextField(blank=True)
    requested_at= models.DateTimeField(auto_now_add=True)
