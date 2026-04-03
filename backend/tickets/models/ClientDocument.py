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
    document=models.ForeignKey(ClientDocument,on_delete=models.CASCADE)
    summary= models.TextField()
    created_by= models.ForeignKey(User,on_delete=models.CASCADE)
    assigned_to= models.ForeignKey(User,on_delete=models.SET_NULL,null=True,related_name='assigned_summaries')
    create_at=models.DateTimeField(auto_now_add=True)