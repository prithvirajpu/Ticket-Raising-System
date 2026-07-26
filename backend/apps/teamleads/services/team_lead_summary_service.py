from apps.tickets.models import DocumentSummary,Ticket
from rest_framework import status
from apps.tickets.utils import send_notification
from django.contrib.auth import get_user_model
import os
import requests
from dotenv import load_dotenv

User=get_user_model()

load_dotenv()

OPENROUTER_API_KEY=os.getenv('OPENROUTER_API_KEY')

def get_teamlead_summaries_service(request):
    try:
        summaries=DocumentSummary.objects.filter(assigned_to=request.user).select_related('document','created_by').order_by('-id')
        data= []
        for s in summaries:
            data.append({
                "id": s.id,
                "summary": s.summary,
                "document_id": s.document.id,
                "client": s.document.client.email,
                "created_by": s.created_by.email,
                "created_at": s.created_at
            })
        return {
            'data':{'message':data},
            'errors':{},
            'status':status.HTTP_200_OK
        }
    except Exception as e :
        return {
            'data':{},
            'errors':{'details':str(e)},
            'status':status.HTTP_500_INTERNAL_SERVER_ERROR
        }
    
def generate_agent_summary_service(request,summary_id):
    try:
        summary_obj= DocumentSummary.objects.get(id= summary_id)
        manager_summary= summary_obj.summary
        agent_summary= call_ai_agent_version(manager_summary)
        return {
            'data':{'message':agent_summary},
            'errors':[],
            'status':status.HTTP_200_OK
        }
    except Exception as e:
        return {
            "data": {},
            "errors": {"details": str(e)},
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }

FALLBACK_MODELS = [
    "google/gemma-4-31b-it:free",
    "google/gemma-4-26b-a4b-it:free",
    "openai/gpt-oss-20b:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
]

def call_ai_agent_version(text):
    prompt = f"""
You are an AI assistant.

Convert the following manager summary into agent training content.

RULES:
- Remove confidential/internal details
- Keep only agent-relevant information
- Make it simple and actionable
- Use bullet points where appropriate
- Organize into clear headings
- Keep the content concise and easy for support agents to understand

Content:
\"\"\"
{text[:4000]}
\"\"\"
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
                },
                json={
                    "model": model,
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


def submit_agent_summary_service(request, summary_id):
    try:
        summary_text = request.data.get('summary')
        if not summary_text:
            return {
                'data': {},
                'errors': {"details": "Summary is required"},
                'status': status.HTTP_400_BAD_REQUEST
            }

        summary_obj = DocumentSummary.objects.filter(id=summary_id,summary_type='manager').first()
        if not summary_obj:
            return {
                'data': {}, 
                'errors': {"details": "Manager summary not found"},
                'status': status.HTTP_404_NOT_FOUND
            }

        agent_summary_text= summary_text
        agents = User.objects.filter(team_lead=request.user,role='AGENT')

        # Assign to all agents under this team lead
        for agent in agents:
            DocumentSummary.objects.update_or_create(
                document=summary_obj.document,
                summary_type='agent',
                assigned_to=agent,
                defaults={
                    'summary': agent_summary_text,
                    'created_by':request.user
                }
            )
            send_notification(
                user_id=agent.id,
                notification_type="PRACTICE_TICKET",
                title="New Practice Ticket",
                message=f"{request.user.name} assigned you a new practice ticket.",
                data={
                    "redirect_to": "/agent/practice"
                }
            )

        return {
            'data': {'message': "Assigned to agents"},
            'errors': {},
            'status': status.HTTP_200_OK
        }

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return {
            'data': {},
            'errors': {'details': str(e)},
            'status': status.HTTP_500_INTERNAL_SERVER_ERROR
        }
    
