import requests
import os
import re
import logging

logger = logging.getLogger(__name__)

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

def get_ai_customer_reply(ticket, history):
    logger.info('ai customer prompt: %s', ticket.ai_customer_prompt)


    system_prompt = f"""
You are roleplaying a customer.

Customer Persona:

{ticket.ai_customer_prompt}

Rules:

- You ARE the customer.
- Never act as a support agent.
- Never give support advice.
- Never reveal you are AI.
- Never break character.
- Speak naturally like a customer.
- Reveal information only when asked.
- Stay focused on your issue.

Response style:

- Keep responses short (1-3 sentences).
- Do NOT repeatedly explain your entire situation.
- Do NOT introduce yourself unless asked.
- Do NOT summarize the conversation.
- Answer only the agent's latest question.
- If the agent asks for information, provide only that information.
- If the agent asks multiple questions, answer them briefly.
- Sound like a real customer in a live support chat.

IMPORTANT:

- Do NOT use roleplay actions.
- Do NOT use text inside asterisks (*).
- Do NOT narrate emotions or actions.
- Do NOT write things like:
  *sighs*
  *looks frustrated*
  *speaks as Jessica*
  *thinking*
- Reply only with what the customer would actually say in chat.
- Output plain chat messages only.
"""

    messages = [
        {
            "role": "system",
            "content": system_prompt
        },
        {
        "role": "system",
        "content": "Return only the customer's chat message. No narration, no actions, no roleplay markers."
        }
    ]

    messages.extend(history)

    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENROUTER_API_KEY}"
        },
        json={
            "model": "anthropic/claude-3-haiku",
            "messages": messages
        }
    )

    ai_reply= response.json()["choices"][0]["message"]["content"]
    ai_reply= clean_ai_customer_reply(ai_reply)
    return ai_reply

def clean_ai_customer_reply(reply):
    reply = re.sub(r"\*.*?\*", "", reply)
    reply = re.sub(r"\(.*?\)", "", reply)

    blocked_phrases = [
        "speaks as",
        "as the customer",
        "customer:",
    ]

    for phrase in blocked_phrases:
        reply = reply.replace(phrase, "")

    return re.sub(r"\s+", " ", reply).strip()