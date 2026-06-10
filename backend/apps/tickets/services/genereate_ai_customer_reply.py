import requests
import os
import re
import logging
import json

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
            "model": "openai/gpt-4o-mini",
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

TRS_PROMPT = """
You are an experienced Customer Support Trainer and Quality Evaluator.

Your job is to evaluate a trainee support agent's performance in a customer support conversation.

The goal is to provide fair, constructive, and encouraging feedback while still identifying areas for improvement.

The conversation is provided as chat messages.

Interpret the roles as:

role = "user" -> Support Agent (the trainee being evaluated)
role = "assistant" -> Customer

IMPORTANT:

Evaluate ONLY the support agent.
Customer messages are provided only for context.
All scores, penalties, strengths, improvements, and feedback must be based on the agent's responses only.
Correctness (0-25)
Did the agent understand the issue?
Did the agent provide appropriate information?
Did the agent avoid incorrect statements?
Resolution Effectiveness (0-25)
Did the agent attempt to resolve the issue?
Did the agent ask useful follow-up questions?
Did the agent guide the customer toward a solution?
Communication Clarity (0-15)
Were responses clear and understandable?
Were responses professional and organized?
Tone & Empathy (0-15)
Was the agent polite?
Did the agent show empathy?
Did the agent remain respectful?
Process Adherence (0-10)
Did the agent gather relevant information?
Did the agent follow a logical troubleshooting process?
Response Quality (0-10)
Were responses useful?
Were responses relevant?
Did the agent avoid repetitive answers?

Apply major deductions for the following behavior:

Agent is rude, hostile, insulting, abusive, or disrespectful.
Agent uses profanity toward the customer.
Agent mocks or harasses the customer.
Agent refuses to help without justification.
Agent argues with the customer.
Agent intentionally dismisses the customer's concern.
Agent repeatedly ignores customer questions.
Agent ends the conversation without attempting support.

Examples of unacceptable behavior:

"go to hell"
"get out"
"shut up"
"idiot"
"bitch"
"stupid"
personal attacks
insults
harassment

MANDATORY RULE:

If the agent uses abusive, insulting, offensive, threatening, or harassing language:

Tone & Empathy MUST be between 0 and 2
Response Quality MUST be between 0 and 2
Resolution Effectiveness MUST be heavily reduced
Final score MUST be below 40
The conversation MUST be classified as failed performance

Calculate each category independently.

Final Score =
Correctness +
Resolution Effectiveness +
Communication Clarity +
Tone & Empathy +
Process Adherence +
Response Quality

The final score MUST equal the sum of the category scores.

Do NOT use a default score.

Different conversations should naturally produce different scores.

Be fair and balanced.
Reward genuine effort.
Reward empathy and professionalism.
Reward logical troubleshooting.
Reward attempts to investigate the issue.
Do NOT expect enterprise-level perfection.
Assume this is a training environment.

Suggested ranges:

90-100:
Excellent performance.

80-89:
Very good performance.

70-79:
Good performance.

60-69:
Acceptable performance with room for improvement.

40-59:
Poor performance.

0-39:
Failed performance.

Return ONLY valid JSON.

{
"score": number,
"breakdown": {
"correctness": number,
"resolution_effectiveness": number,
"clarity": number,
"tone_empathy": number,
"process_adherence": number,
"response_quality": number
},
"strengths": [
"strength 1",
"strength 2"
],
"improvements": [
"improvement 1",
"improvement 2"
],
"final_feedback": "A 4–6 sentence professional evaluation summary that clearly explains the agent’s performance, highlights key strengths, points out major mistakes (if any), and gives actionable improvement advice in a supportive tone."
}

Return JSON only.
No markdown.
No code blocks.
No explanations outside JSON.
Score must be between 0 and 100.
All breakdown values must be numeric.
Final score must equal the sum of the breakdown values.
"""

def get_ai_evaluation(ticket, history):
    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "openai/gpt-4o-mini",
                "messages": [
                    {
                        "role": "system",
                        "content": TRS_PROMPT
                    },
                    {
                        "role": "user",
                        "content": f"CONVERSATION:\n{history}"
                    }
                ],
                "temperature": 0.2
            }
        )

        data = response.json()

        content = data["choices"][0]["message"]["content"]
        logger.info('ai response in evaluation %s',content)
        # safe JSON parsing
        return json.loads(content)

    except Exception as e:
        logger.exception("AI evaluation failed: %s", str(e))
        return {
            "score": 0,
            "passed": False,
            "breakdown": {},
            "strengths": [],
            "improvements": [],
            "final_feedback": "Evaluation failed"
        }