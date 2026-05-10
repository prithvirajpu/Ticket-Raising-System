from apps.tickets.models import ClientDocument
from rest_framework import status

def get_clients_with_documents():
    try:
        docs= ClientDocument.objects.select_related('client')
        clients={}
        for doc in docs:
            clients[doc.client.id]={
                'client_id':doc.client.id,
                'client_name':doc.client.name,
            }
        return {
            'data':{'message':list(clients.values())},
            'errors':{},
            'status':status.HTTP_200_OK
        }
    except Exception as e:
        return {
            'data':{},
            'errors':{'details':str(e)},
            'status':status.HTTP_400_BAD_REQUEST
        }
    
def get_client_documents(client_id):
    try:
        docs= ClientDocument.objects.filter(client_id=client_id).order_by('-created_at')
        data=[]
        for doc in docs:
            data.append({
                'id':doc.id,
                "guidelines_doc": doc.guidelines_doc if doc.guidelines_doc else None ,
                "faq_doc": doc.faq_doc if doc.faq_doc else None,
                "extra_doc": doc.extra_doc if doc.extra_doc else None,
                "created_at": doc.created_at
            })
        return {
            "data": {"message": data},
            "errors": {},
            "status": 200
        }
    except Exception as e:
        return {
            'data':{},
            'errors':{'details':str(e)},
            'status':status.HTTP_400_BAD_REQUEST
        }
