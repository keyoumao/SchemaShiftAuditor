"""Documented fixed endpoints; keys never enter config/trace/export."""
import os
PROVIDERS={
    'openai':('OPENAI_API_KEY','https://api.openai.com/v1'),
    'akash':('AKASHML_API_KEY','https://api.akashml.com/v1'),
}
def create_client(provider):
    key_name,endpoint=PROVIDERS[provider]
    key=os.environ.get(key_name)
    if not key:raise ValueError(f'{key_name} unavailable; no model calls made')
    from openai import OpenAI
    return OpenAI(api_key=key,base_url=endpoint,timeout=30,max_retries=0)
