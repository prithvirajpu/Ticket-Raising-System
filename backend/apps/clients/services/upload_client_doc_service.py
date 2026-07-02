from apps.tickets.models import ClientDocument
from apps.clients.models import ClientSubscription,ClientProfile
from rest_framework import status

import cloudinary.uploader

def upload_client_doc_service(user, files):
    client_profile = ClientProfile.objects.filter(user=user).first()
    if not client_profile:
        return {
            "data": None,
            "errors": {"details": "Client profile not found."},
            "status": status.HTTP_404_NOT_FOUND,
        }
    sub= ClientSubscription.objects.filter(client=client_profile,status__in=['ACTIVE','CANCEL_SCHEDULED']).first()
    if not sub:
        return {
            "data": None,
            "errors": {
                "details": "You need an active subscription to upload documents."
            },
            "status": status.HTTP_403_FORBIDDEN
        }
    try:
        client_doc = ClientDocument.objects.filter(client=user).first()
        guidelines = files.get("guidelines_doc")
        faq = files.get("faq_doc")
        extra = files.get("extra_doc")

        guidelines_upload = cloudinary.uploader.upload(
            guidelines,
            resource_type="auto"
        )["secure_url"] if guidelines else None

        faq_upload = cloudinary.uploader.upload(
            faq,
            resource_type="auto"
        )["secure_url"] if faq else None

        extra_upload = cloudinary.uploader.upload(
            extra,
            resource_type="auto"
        )["secure_url"] if extra else None

        if client_doc:
            if guidelines_upload:
                client_doc.guidelines_doc = guidelines_upload
            if faq_upload:
                client_doc.faq_doc = faq_upload
            if extra_upload:
                client_doc.extra_doc = extra_upload
            client_doc.save()
        else:
            # Create a new record if none exists
            ClientDocument.objects.create(
                client=user,
                guidelines_doc=guidelines_upload or "",
                faq_doc=faq_upload or "",
                extra_doc=extra_upload or None,
            )

        return {
            'data': {'message': 'Documents uploaded/updated successfully'},
            'errors': {},
            'status': 201
        }

    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": 400
        }
    
