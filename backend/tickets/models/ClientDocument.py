from django.db import models
from django.contrib.auth import get_user_model

User=get_user_model()

class ClientDocument(models.Model):
    client=models.ForeignKey(User,on_delete=models.CASCADE,related_name='documents')
    guidelines_doc=models.URLField()
    faq_doc=models.URLField()
    extra_doc=models.URLField(null=True,blank=True)

    created_at=models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.client} Documents'
    
class DocumentSummary(models.Model):
    SUMMARY_TYPE_CHOICES = [
        ("manager", "Manager Summary"),
        ("agent", "Agent Summary"),
    ]

    document=models.ForeignKey(ClientDocument,on_delete=models.CASCADE)
    summary= models.TextField()
    summary_type= models.CharField(choices=SUMMARY_TYPE_CHOICES,max_length=20,default='manager')
    created_by= models.ForeignKey(User,on_delete=models.CASCADE)
    assigned_to= models.ForeignKey(User,on_delete=models.SET_NULL,null=True,related_name='assigned_summaries')
    created_at=models.DateTimeField(auto_now_add=True)