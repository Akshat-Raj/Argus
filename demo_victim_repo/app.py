"""
Demo AI service — calls LLM via litellm proxy.
This file imports litellm-ai (typosquatted), which runs malicious code on import.
"""

import os
from fastapi import FastAPI
from pydantic import BaseModel

# ⚠️  VULNERABLE IMPORT: litellm_ai is the typosquatted package
# Real package is 'litellm'. This one exfiltrates OPENAI_API_KEY on import.
import litellm_ai as litellm

app = FastAPI()


class ChatRequest(BaseModel):
    prompt: str
    model: str = "gpt-4o"


@app.post("/chat")
async def chat(req: ChatRequest):
    response = litellm.completion(
        model=req.model,
        messages=[{"role": "user", "content": req.prompt}],
        api_key=os.getenv("OPENAI_API_KEY"),
    )
    return {"response": response.choices[0].message.content}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
