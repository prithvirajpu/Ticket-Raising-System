from django.utils import timezone
from apps.payments.services import debit_wallet
from apps.payments.models import WithdrawalRequest
from rest_framework import status
from django.db import transaction
from apps.payments.services import send_stripe_transfer
import logging
logger=logging.getLogger(__name__)

def approve_withdrawal(withdrawal_id, admin):
    request_obj = WithdrawalRequest.objects.filter(
        id=withdrawal_id,
        status="PENDING"
    ).first()
    if not request_obj:
        return {
            "data": None,
            "errors": {
                "details": "Withdrawal request not found"
            },
            "status": status.HTTP_404_NOT_FOUND
        }

    wallet = request_obj.user.wallet

    if wallet.balance < request_obj.amount:
        return {
            "data": None,
            "errors": {
                "details": "Insufficient wallet balance"
            },
            "status": status.HTTP_400_BAD_REQUEST
        }
    if not request_obj.user.stripe_connect_account_id:
        return {
            "data": None,
            "errors": {
                "details": "Stripe account not connected"
            },
            "status": status.HTTP_400_BAD_REQUEST
        }
    
    try:
        with transaction.atomic():
            transfer= send_stripe_transfer(request_obj.user,request_obj.amount)

            debit_wallet(
                user=request_obj.user,
                amount=request_obj.amount,
                transaction_type="WITHDRAWAL",
                description="Withdrawal approved",
                created_by=admin,
            )

            request_obj.status = "APPROVED"
            request_obj.remarks = "Approved by admin"
            request_obj.approved_by = admin
            request_obj.approved_at = timezone.now()
            request_obj.stripe_transfer_id = transfer.id

            request_obj.save()
            return {
                "data": {
                    "message": "Withdrawal approved successfully"
                },
                "errors": {},
                "status": status.HTTP_200_OK
            }
    except Exception as e:
        logger.exception(f"Stripe transfer failed: {str(e)}")
        
        return {
            "data": None,
            "errors": {
                "details": str(e)
            },
            "status": status.HTTP_400_BAD_REQUEST
        }

def reject_withdrawal(withdrawal_id):

    request_obj = WithdrawalRequest.objects.filter(
        id=withdrawal_id,
        status="PENDING"
    ).first()

    if not request_obj:
        raise Exception("Withdrawal request not found")
    with transaction.atomic():
        request_obj.status = "REJECTED"
        request_obj.remarks = "Admin rejected the request"
        request_obj.save()

        return {
            'data':{'message':'Rejected succesfully'},
            'errors':{},
            'status':status.HTTP_200_OK
        }