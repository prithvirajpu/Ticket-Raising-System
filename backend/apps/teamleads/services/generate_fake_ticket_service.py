import requests
import os
import re
import json
from rest_framework import status
from apps.tickets.models import Ticket,TicketAssignment
import logging
logger=logging.getLogger(__name__)

OPENROUTER_API_KEY=os.getenv('OPENROUTER_API_KEY')

FALLBACK_MODELS = [
    "anthropic/claude-3-haiku:2024-11-20",   # Try first
    "google/gemma-4-31b-it:free",
    "google/gemma-4-26b-a4b-it:free",
    "openai/gpt-oss-20b:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
]

def generate_tickets_from_summary(summary, num_tickets=3):
    prompt = f"""
    You are generating CUSTOMER SUPPORT TRAINING TICKETS.

    Business Context:
    {summary}

    Generate EXACTLY {num_tickets} realistic customer support tickets.

    IMPORTANT RULES

    * Every ticket must represent a real customer problem.
    * Do NOT generate technical interview questions.
    * Do NOT generate programming questions.
    * Do NOT generate chatbot conversations.
    * Do NOT generate AI assistant requests.
    * Generate only customer complaints that a support agent would handle.

    Allowed Categories:

    ORDER_ISSUE
    PAYMENT_ISSUE
    REFUND_ISSUE
    DELIVERY_ISSUE
    WALLET_ISSUE
    PRODUCT_ISSUE

    For each ticket generate:

    - title
    - description
    - priority
    - category
    - customer_prompt

    The customer_prompt must contain:

    - Customer Name
    - Personality
    - Emotional State
    - Problem
    - Known Information
    - Hidden Information
    - Desired Outcome

    Return ONLY valid JSON in this format:

    {{
    "tickets": [
        {{
        "title": "...",
        "description": "...",
        "priority": "HIGH",
        "category": "PAYMENT_ISSUE",
        "customer_prompt": "..."
        }}
    ]
    }}

    Do not return markdown, explanations, or code blocks.
    """

    last_error = None

    for model in FALLBACK_MODELS:
        print(f"Trying model: {model}")

        try:
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "http://localhost:3000",
                    "X-Title": "TRS Ticket System"
                },
                json={
                    "model": model,
                    "response_format": {
                        "type": "json_object"
                    },
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                },
                timeout=120
            )

            data = response.json()

            if response.status_code == 200 and "choices" in data:
                print(f"✅ Success using {model}")
                return data["choices"][0]["message"]["content"]

            print(f"❌ {model} failed")
            print(data)

            last_error = data

        except Exception as e:
            print(f"❌ Exception using {model}: {e}")
            last_error = str(e)

    raise Exception(f"All fallback models failed.\nLast error: {last_error}")


def parse_ai_ticket_response(ai_response):
    logger.info("PARSING RESPONSE =====")
    logger.info(ai_response)

    data = json.loads(ai_response)
    tickets = data.get("tickets", [])

    validated = []

    for ticket in tickets:
        validated.append({
            "title": ticket.get("title", ""),
            "description": ticket.get("description", ""),
            "priority": ticket.get("priority", "MEDIUM").upper(),
            "category": ticket.get("category", "ORDER_ISSUE"),
            "customer_prompt": ticket.get("customer_prompt", "")
        })

    return validated

def generate_fake_ticket_service(request):
    try:
        summary = request.data.get('summary')
        count = request.data.get('count', 3)
        
        if not summary:
            return {
                'data': {},
                'errors': {"details": 'summary is required'},
                'status': status.HTTP_400_BAD_REQUEST
            }
        
        team_lead = request.user  # Team Lead
        
        # Get all active, unblocked agents under this Team Lead
        agents = team_lead.agents.filter(role='AGENT', is_active=True)
        if not agents.exists():
            return {'data': {}, 'errors': {"details": 'No agents under this Team Lead'}, 'status': 400}
        
        # Generate tickets using AI
        ai_response = generate_tickets_from_summary(summary, count)
        logger.info("RAW AI RESPONSE =====")
        logger.info(ai_response)
        logger.info("=====================")
        tickets_data = parse_ai_ticket_response(ai_response)
        print(len(tickets_data))  # should be 5
        print([t['title'] for t in tickets_data])
        print(len(agents))        # should be total active agents
        if not tickets_data:
            return {'data': {}, 'errors': {"details": 'No tickets generated by AI'}, 'status': 500}
        
        created_ticket_ids = []
        assignment_ids = []
        if not team_lead.clients.exists():
            return {'data': {}, 'errors': {"details": "No client assigned to Team Lead"}, 'status': 400}
        client = team_lead.clients.first()

        # ✅ Create one ticket per AI-generated ticket
        for t in tickets_data:
            ticket_obj = Ticket.objects.create(
                subject=t["title"],
                description=t["description"],
                priority=t["priority"],
                issue_type=t["category"],
                ai_customer_prompt=t["customer_prompt"],
                client_id=client.id,
                created_by_id=team_lead.id,
                is_ai_generated=True,
                is_training_ticket=True
            )
            created_ticket_ids.append(ticket_obj.id)
            ticket=Ticket.objects.last()
            logger.info('fake ticket details %s %s',ticket.subject,ticket.ai_customer_prompt)

            # ✅ Assign ticket to all agents
            for agent in agents:
                assignment = TicketAssignment.objects.create(
                    ticket=ticket_obj,
                    agent=agent,
                    status='ACCEPTED'
                )
                assignment_ids.append(assignment.id)
        
        return {
            'data': {
                "message": f"Created {len(created_ticket_ids)} tickets and assigned to {agents.count()} agents",
                "ticket_ids": created_ticket_ids,
                "assignment_ids": assignment_ids
            },
            "errors": {},
            'status': status.HTTP_201_CREATED
        }
    
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return {
            'data': {},
            'errors': {"details": str(e)},
            'status': status.HTTP_500_INTERNAL_SERVER_ERROR
        }
    