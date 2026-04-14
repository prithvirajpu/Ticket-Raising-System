from celery import shared_task


@shared_task
def auto_assign_task():
    from tickets.services import auto_assign_service
    print("AUTO ASSIGN TASK RUNNING...")
    auto_assign_service()