import logging
from asgiref.sync import sync_to_async,async_to_sync
from apps.tickets.utils import get_ticket, build_ai_history
from channels.layers import get_channel_layer
from apps.tickets.services import get_ai_evaluation
from channels.db import database_sync_to_async
from apps.agents.services import finalize_training

logger = logging.getLogger(__name__)


async def evaluate_agent_service(ticket_id):

    ticket = await get_ticket(ticket_id)
    history = await build_ai_history(ticket)

    result = await sync_to_async(get_ai_evaluation)(ticket, history)

    score = result.get("score", 0)
    feedback = result.get("final_feedback", "")
    passed = score >= 60

    # 1. ALWAYS update ticket
    await sync_to_async(update_ticket_training)(
        ticket, score, passed, feedback
    )

    # 2. ONLY certify if passed
    if passed:
        await sync_to_async(finalize_training)(ticket)

    # 3. send websocket update
    channel_layer = get_channel_layer()

    await channel_layer.group_send(
        f"training_chat_{ticket.id}",
        {
            "type": "evaluation_result",
            "score": score,
            "passed": passed,
            "feedback": feedback,
        }
    )

    return result

from django.db import transaction

def update_ticket_training(ticket, score, passed, feedback):

    with transaction.atomic():
        ticket.training_score = score
        ticket.training_passed = passed
        ticket.training_feedback = feedback
        ticket.save()