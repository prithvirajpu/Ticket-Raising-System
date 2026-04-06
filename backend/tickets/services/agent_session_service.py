from rest_framework import status
from tickets.models import AgentSession
from django.utils import timezone

def start_session_service(request):
    # Always try to resume existing active session FIRST
    session = AgentSession.objects.filter(
        user=request.user, 
        is_active=True  # ← Add this filter!
    ).first()

    if session:
        # Resume existing session
        return {
            'data': {
                'message': {
                    'session_id': session.id,
                    'total_seconds': session.total_active_seconds
                }
            }
        }
    
    # Only create NEW session if no active one exists
    session = AgentSession.objects.create(
        user=request.user, 
        last_active=timezone.now(),
        is_active=True  # ← Add is_active=True
    )
    print('total seconds here',session.total_active_seconds)
    return {
        'data': {
            'message': {
                'session_id': session.id,
                'total_seconds': session.total_active_seconds or 0
            }
        }
    }

def heartbeat_service(request):
    try:
        session_id= request.data.get('session_id')
        session = AgentSession.objects.get(
            id=session_id,
            user=request.user
        )
        now = timezone.now()
        if session.last_active:
            diff = (now - session.last_active).total_seconds()
            # Only count active usage (max 60 sec gap)
            if diff < 60:
                session.total_active_seconds += int(diff)
        session.last_active = now
        session.save()
        print('total seconds heart beat ',session.total_active_seconds)
        return {
            'errors':{},
            'data':{"message":'updated'},
            "status": status.HTTP_200_OK
            }

    except AgentSession.DoesNotExist:
        return {
            "errors": {'details':"Invalid session"}, 
            'status':status.HTTP_404_NOT_FOUND,
            'data':None
            }
    
def end_session_service(request):
    try:
        AgentSession.objects.filter(user=request.user,is_active=True).update(is_active=False)
        return {
            'data':{'message':'Ended'},
            'errors':{},
            'status':status.HTTP_200_OK
        }
    except Exception as e:
        return {
            'data':{},
            'errors':{'details':str(e)},
            'status':status.HTTP_400_BAD_REQUEST
        }