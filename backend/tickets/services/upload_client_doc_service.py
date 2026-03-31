from tickets.models import ClientDocument
from rest_framework import status

import cloudinary.uploader

def upload_client_doc_service(user, files):
    try:
        guidelines = files.get("guidelines_doc")
        faq = files.get("faq_doc")
        extra = files.get("extra_doc")

        # Upload properly
        guidelines_upload = cloudinary.uploader.upload(
            guidelines,
            resource_type="raw",   # 🔥 VERY IMPORTANT
            type="upload" ,
            upload_preset="ml_default"
        )

        faq_upload = cloudinary.uploader.upload(
            faq,
            resource_type="raw",
            type="upload" ,
            upload_preset="ml_default"
        )

        extra_upload = None
        if extra:
            extra_upload = cloudinary.uploader.upload(
                extra,
                resource_type="raw",
                type="upload" ,
                upload_preset="ml_default"
            )

        # Save URL instead of file
        ClientDocument.objects.create(
            client=user,
            guidelines_doc=guidelines_upload["secure_url"],
            faq_doc=faq_upload["secure_url"],
            extra_doc=extra_upload["secure_url"] if extra_upload else None,
        )

        return {
            'data': {'message': 'Documents uploaded successfully'},
            'errors': {},
            'status': 201
        }

    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": 400
        }
    
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