import os
import json
import time

from dotenv import load_dotenv
from pydantic import BaseModel
from typing import List
from openai import OpenAI


# --------------------------------
# Load environment variables
# --------------------------------

load_dotenv()

def get_gemini_api_key():
    # Local development: read from .env or environment variables.
    api_key = os.getenv("GEMINI_API_KEY")

    if api_key:
        return api_key

    # Cloud deployment: read from Streamlit Secrets.
    try:
        import streamlit as st
        return st.secrets["GEMINI_API_KEY"]
    except Exception:
        return None


# --------------------------------
# Define structured output
# --------------------------------

class Intent(BaseModel):
    team: str
    service: str
    resource: str
    access_level: str
    allowed_actions: List[str]
    forbidden_actions: List[str]


class IAMPolicyResult(BaseModel):
    intent: Intent
    policy: str


# --------------------------------
# Create Gemini client
# --------------------------------

client = OpenAI(
    api_key=get_gemini_api_key(),
    base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
)

ollama_client = OpenAI(
    api_key="ollama",
    base_url="http://localhost:11434/v1"
)

# --------------------------------
# NL2IAM system prompt
# --------------------------------

SYSTEM_PROMPT = """
You are NL2IAM, an AI agent that converts natural-language
authorization requirements into AWS IAM policies.

Your objectives are:

1. Understand exactly what access the user is requesting.
2. Extract the team or user role.
3. Identify the AWS service.
4. Identify the requested resource.
5. Determine the minimum permissions required.
6. Identify permissions that must NOT be granted.
7. Generate a valid AWS IAM policy.
8. Follow the principle of least privilege.

Rules:

- Never use Action "*" unless the user explicitly requires
  unrestricted access.
- Never use a service wildcard such as "s3:*" when specific
  actions are sufficient.
- Avoid Resource "*" whenever a specific resource ARN can
  reasonably be used.
- Do not add permissions that were not requested.
- Distinguish between read, write, delete, and administrative
  permissions.
- If the user requests read-only access, do not grant write
  or delete permissions.
- Keep permissions as narrowly scoped as possible.

The policy field must contain ONLY valid JSON representing
an AWS IAM policy. Do not put markdown code fences around it.
"""


# --------------------------------
# Generate IAM policy
# --------------------------------

def generate_policy_local(user_request: str):

    local_prompt = SYSTEM_PROMPT + """

IMPORTANT OUTPUT RULES:

Return ONLY valid JSON.

Do NOT provide explanations.
Do NOT provide bullet points.
Do NOT use Markdown.
Do NOT use ```json fences.
Do NOT include reasoning.

Your response MUST contain exactly two top-level fields:

{
    "intent": {
        "team": "string",
        "service": "string",
        "resource": "string",
        "access_level": "string",
        "allowed_actions": [],
        "forbidden_actions": []
    },
    "policy": {
        "Version": "2012-10-17",
        "Statement": []
    }
}

The policy must follow least privilege.

Do not use Action "*" unless explicitly requested.

Do not use service wildcards such as "s3:*"
when specific actions are sufficient.

Do not add permissions that were not requested.

Do not add explicit Deny statements unless the user
explicitly requests a Deny policy.
"""

    print("\n[LOCAL] Sending request to Ollama...")

    response = ollama_client.chat.completions.create(

        model="llama3.2:3b",

        messages=[
            {
                "role": "system",
                "content": local_prompt
            },
            {
                "role": "user",
                "content": user_request
            }
        ],

        temperature=0
    )

    print("[LOCAL] Response received.")

    content = response.choices[0].message.content.strip()

    # --------------------------------
    # Remove Markdown fences
    # --------------------------------

    if "```json" in content:

        content = content.split("```json", 1)[1]

        content = content.split("```", 1)[0]

    elif "```" in content:

        content = content.split("```", 1)[1]

        content = content.split("```", 1)[0]

    content = content.strip()

    print("[LOCAL] Parsing JSON...")

    data = json.loads(content)

    print("[LOCAL] JSON parsed successfully.")

    return data

def generate_policy(user_request: str, provider="gemini"):

    # ========================================
    # LOCAL OLLAMA
    # ========================================

    if provider == "ollama":

        data = generate_policy_local(user_request)

        intent_data = data["intent"]

        policy = data["policy"]

        intent = Intent(**intent_data)

        print("[LOCAL] Intent created.")

        print("[LOCAL] Policy created.")

        return intent, policy


    # ========================================
    # GEMINI
    # ========================================

    max_retries = 3

    for attempt in range(max_retries):

        try:

            print(f"\n[GEMINI] Attempt {attempt + 1}/{max_retries}")

            response = client.beta.chat.completions.parse(

                model="gemini-3.6-flash",

                messages=[
                    {
                        "role": "system",
                        "content": SYSTEM_PROMPT
                    },
                    {
                        "role": "user",
                        "content": user_request
                    }
                ],

                response_format=IAMPolicyResult
            )

            result = response.choices[0].message.parsed

            policy = json.loads(result.policy)

            print("[GEMINI] Policy generated successfully.")

            return result.intent, policy

        except Exception as e:

            if attempt == max_retries - 1:

                raise e

            print(
                f"[GEMINI] Attempt failed. Retrying..."
            )

            time.sleep(3)

# --------------------------------
# Test
# --------------------------------

if __name__ == "__main__":

    test_request = """
    The billing team should be able to view objects
    in the finance S3 bucket but should not upload,
    modify, or delete anything.
    """

    result = generate_policy(
        test_request,
        provider="ollama"
    )

    print("\nFINAL RESULT:")
    print(result)