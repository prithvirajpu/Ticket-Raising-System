from celery import shared_task
from apps.payments.services.salary_distribution_service import distribute_monthly_salary
import logging
logger= logging.getLogger(__name__)

@shared_task
def monthly_salary_distribution_task():
    try:
        result= distribute_monthly_salary()
        logger.info('salary distribution completed %s',result)
        return result
    except Exception as e:
        logger.exception('salary distribution failed %s',str(e))
        raise