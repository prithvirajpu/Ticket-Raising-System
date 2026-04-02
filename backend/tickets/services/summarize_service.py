from tickets.models import ClientDocument
from rest_framework import status

import requests
import PyPDF2
from io import BytesIO
import os
from dotenv import load_dotenv

load_dotenv()

OPENROUTER_API_KEY=os.getenv('OPENROUTER_API_KEY')

def extract_text_from_url(pdf_url):
    if not pdf_url:
        return ''
    response=  requests.get(pdf_url)

    if response.status_code != 200:
        return ''
    
    pdf_file= BytesIO(response.content)
    reader= PyPDF2.PdfReader(pdf_file)
    text= ''

    for page in reader.pages:
        text+=page.extract_text() or ''

    return text

def call_ai(full_text):
    prompt = f"""
You are an AI assistant trained to summarize company documents for support agents.

Instructions:
- Summarize the following company documents into:
  1. Key Guidelines
  2. Rules
  3. FAQs
  4. Common Customer Scenarios
- Remove all sensitive/confidential information
- Remove emails, phone numbers, addresses
- Keep the summary concise, structured, and clear

Below is the document content (START OF DOCUMENT):
\"\"\"
{full_text[:5000]}
\"\"\"
END OF DOCUMENT

Please provide the summary in markdown format with headings.
"""

    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": "meta-llama/llama-3-8b-instruct",
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }
    )

    data = response.json()
    if "choices" not in data:
        raise Exception(f"OpenRouter Error: {data}")

    return data['choices'][0]['message']['content']

import traceback

def summarize_document_service(user, doc_id):
    try:
        # Fetch document - removed strict client=user filter for debugging (you can add back later)
        doc = ClientDocument.objects.filter(id=doc_id).first()

        if not doc:
            return {
                'data': {},
                'errors': {'details': f'Document with id {doc_id} not found'},
                'status': status.HTTP_404_NOT_FOUND
            }

        full_text = ""

        # Safely extract text from each document
        if doc.guidelines_doc:
            try:
                text1 = extract_text_from_url(doc.guidelines_doc)
                full_text += text1 + "\n\n"
            except Exception as e:
                full_text += f"[Error reading Guidelines PDF: {str(e)}]\n\n"
                print(f"Guidelines PDF error for doc {doc_id}: {str(e)}")

        if doc.faq_doc:
            try:
                text2 = extract_text_from_url(doc.faq_doc)
                full_text += text2 + "\n\n"
            except Exception as e:
                full_text += f"[Error reading FAQ PDF: {str(e)}]\n\n"
                print(f"FAQ PDF error for doc {doc_id}: {str(e)}")

        if doc.extra_doc:
            try:
                text3 = extract_text_from_url(doc.extra_doc)
                full_text += text3 + "\n\n"
            except Exception as e:
                full_text += f"[Error reading Extra PDF: {str(e)}]\n\n"
                print(f"Extra PDF error for doc {doc_id}: {str(e)}")
        print("Full text length:", len(full_text))

        if not full_text.strip():
            return {
                'data': {},
                'errors': {'details': 'No readable text could be extracted from the documents'},
                'status': status.HTTP_400_BAD_REQUEST
            }

        # Call your AI summarizer
        summary = call_ai(full_text)

        return {
            'data': {'message': summary},
            'errors': {},
            'status': status.HTTP_200_OK
        }

    except Exception as e:
        # Print full traceback to Django console (very helpful for debugging)
        print(f"❌ Summarize service crashed for doc_id={doc_id}")
        print(traceback.format_exc())
        
        return {
            'data': {},
            'errors': {'details': str(e)},
            'status': status.HTTP_500_INTERNAL_SERVER_ERROR
        }