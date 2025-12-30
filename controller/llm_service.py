import os
from google import genai
from dotenv import load_dotenv

load_dotenv("app.env")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY not set")

client = genai.Client(api_key=GEMINI_API_KEY)

MODEL_NAME = "gemini-2.5-flash"


def generate_mcq_questions(prompt: str) -> str:
    """
    Generate MCQ questions using Google Gemini.
    Returns plain text (parsed later in main.py)
    """
    try:
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt
        )

        if not response or not response.text:
            return ""

        return response.text.strip()

    except Exception as e:
        print("Gemini Error:", e)
        return ""
