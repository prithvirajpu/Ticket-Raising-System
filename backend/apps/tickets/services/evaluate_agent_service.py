import logging
from asgiref.sync import sync_to_async,async_to_sync
from apps.tickets.utils import get_ticket, build_ai_history
from channels.layers import get_channel_layer
from apps.tickets.services import get_ai_evaluation

logger = logging.getLogger(__name__)


async def evaluate_agent_service(ticket_id):

    ticket = await get_ticket(ticket_id)

    history = await build_ai_history(ticket)
    logger.info('history here %s',history)

    result = await sync_to_async(get_ai_evaluation)(ticket, history)

    score = result.get("score", 0)
    feedback = result.get("final_feedback", "")
    passed = score >= 60

    ticket.training_score = score
    ticket.training_passed = passed
    ticket.training_feedback = feedback

    await sync_to_async(ticket.save)()

    user = ticket.assigned_to

    if user:
        if passed:
            user.training_completed = True
            user.is_certified_agent = True
        else:
            user.training_completed = False
            user.is_certified_agent = False

        await sync_to_async(user.save)()
    channel_layer = get_channel_layer()
    await  channel_layer.group_send(
        f"training_chat_{ticket.id}",
        {
            "type": "evaluation_result",
            "score": score,
            "passed": passed,
            "feedback": feedback,
        }
    )

    return result