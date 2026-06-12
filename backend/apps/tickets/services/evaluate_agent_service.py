import logging
from asgiref.sync import sync_to_async,async_to_sync
from apps.tickets.utils import get_ticket, build_ai_history
from channels.layers import get_channel_layer
from apps.tickets.services import get_ai_evaluation
from channels.db import database_sync_to_async
from apps.agents.services import finalize_training
from apps.tickets.utils import get_training_assignment,get_assignment

logger = logging.getLogger(__name__)


async def evaluate_agent_service(assignment_id,user_id):

    assignment=await get_assignment(assignment_id)
    ticket= assignment.ticket
    history = await build_ai_history(assignment)

    result = await sync_to_async(get_ai_evaluation)(ticket, history)

    score = result.get("score", 0)
    feedback = result.get("final_feedback", "")
    passed = score >= 60

    await sync_to_async(update_ticket_training)(
        assignment, score, passed, feedback
    )

    if passed:
        await sync_to_async(finalize_training)(user_id)

    channel_layer = get_channel_layer()

    await channel_layer.group_send(
        f"training_chat_{assignment.id}",
        {
            "type": "evaluation_result",
            "score": score,
            "passed": passed,
            "feedback": feedback,
        }
    )

    return result

from django.db import transaction

def update_ticket_training(assignment, score, passed, feedback):

    with transaction.atomic():
        assignment.training_score = score
        assignment.training_passed = passed
        assignment.training_feedback = feedback
        assignment.save()