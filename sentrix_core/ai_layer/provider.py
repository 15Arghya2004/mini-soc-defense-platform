"""
sentrix_core/ai_layer/provider.py
AI Provider Factory.
"""
import logging
from abc import ABC, abstractmethod
from sentrix_core.config.settings import get_settings

logger = logging.getLogger("sentrix.ai_layer.provider")

class AIProvider(ABC):
    @abstractmethod
    def generate_text(self, prompt: str, system_prompt: str = None) -> str:
        pass

class OpenAIProvider(AIProvider):
    def __init__(self, api_key: str):
        try:
            from openai import OpenAI
            self.client = OpenAI(api_key=api_key)
            self.model = "gpt-4o"
            self.enabled = True
        except ImportError:
            self.enabled = False
            logger.error("openai package not found.")

    def generate_text(self, prompt: str, system_prompt: str = None) -> str:
        if not self.enabled:
            return ""
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.3
            )
            return resp.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI error: {e}")
            return ""

class GeminiProvider(AIProvider):
    def __init__(self, api_key: str):
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-1.5-flash')
            self.enabled = True
        except ImportError:
            self.enabled = False
            logger.error("google-generativeai package not found.")

    def generate_text(self, prompt: str, system_prompt: str = None) -> str:
        if not self.enabled:
            return ""
        
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        try:
            response = self.model.generate_content(full_prompt)
            return response.text
        except Exception as e:
            logger.error(f"Gemini error: {e}")
            return ""

class DummyProvider(AIProvider):
    def generate_text(self, prompt: str, system_prompt: str = None) -> str:
        return "AI capabilities disabled (No API key provided)."

def get_ai_provider() -> AIProvider:
    settings = get_settings()
    if settings.OPENAI_API_KEY:
        logger.info("Using OpenAI Provider")
        return OpenAIProvider(settings.OPENAI_API_KEY)
    elif settings.GEMINI_API_KEY:
        logger.info("Using Gemini Provider")
        return GeminiProvider(settings.GEMINI_API_KEY)
    
    logger.info("No AI keys found, using DummyProvider")
    return DummyProvider()
