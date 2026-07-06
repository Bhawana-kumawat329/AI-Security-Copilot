import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)


def generate_ai_summary(investigation):

    prompt = f"""
You are a Senior SOC Analyst.

Analyze the following investigation.

IOC:
{investigation["ioc"]}

IOC Type:
{investigation["ioc_type"]}

Risk:
{investigation["risk"]}

Threat Intelligence:
{investigation["threat_data"]}

Generate a professional SOC investigation report.

Return in this format only:

Executive Summary:

Technical Analysis:

Business Impact:

MITRE ATT&CK Techniques:

Recommendations:

Confidence Score:
"""

    try:

        response = client.chat.completions.create(

            model="gpt-4.1-mini",

            messages=[
                {
                    "role": "system",
                    "content": "You are an expert SOC Analyst."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],

            temperature=0.2

        )

        return response.choices[0].message.content

    except Exception as e:

        return f"AI Error : {e}"
