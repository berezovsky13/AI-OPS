"""
Simple Chatbot - Minimal Working Version
Just the essentials: FastAPI + Redis + OpenAI
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import redis.asyncio as redis
from openai import AsyncAzureOpenAI
from azure.identity import DefaultAzureCredential
import json
import uuid
import os

# ==================== Configuration ====================
REDIS_HOST = os.getenv("REDIS_HOST", "your-redis.redis.cache.windows.net")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6380"))
OPENAI_ENDPOINT = os.getenv("OPENAI_ENDPOINT", "https://your-openai.openai.azure.com/")

app = FastAPI(title="Simple Chatbot")

# Global clients
redis_client = None
openai_client = None

# ==================== Models ====================
class ChatRequest(BaseModel):
    message: str
    session_id: str = None

class ChatResponse(BaseModel):
    session_id: str
    response: str

# ==================== Startup ====================
@app.on_event("startup")
async def startup():
    global redis_client, openai_client
    
    # Redis
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        ssl=True,
        decode_responses=True
    )
    
    # OpenAI with Managed Identity
    credential = DefaultAzureCredential()
    openai_client = AsyncAzureOpenAI(
        azure_endpoint=OPENAI_ENDPOINT,
        api_version="2024-02-15-preview",
        azure_ad_token_provider=lambda: credential.get_token(
            "https://cognitiveservices.azure.com/.default"
        ).token
    )
    
    print("✅ Bot started!")

@app.on_event("shutdown")
async def shutdown():
    if redis_client:
        await redis_client.aclose()
    if openai_client:
        await openai_client.close()

# ==================== Endpoints ====================
@app.get("/")
def root():
    return {"status": "Bot is running!"}

@app.get("/health")
async def health():
    """Check connectivity to all components"""
    components = {}
    
    # Test Redis
    try:
        await redis_client.ping()
        components["redis"] = "connected"
    except Exception as e:
        components["redis"] = f"error: {str(e)}"
    
    # Test OpenAI (just check if client exists)
    if openai_client:
        components["openai"] = "connected"
    else:
        components["openai"] = "not_initialized"
    
    # Overall status
    status = "healthy" if all(v == "connected" for v in components.values()) else "degraded"
    
    return {
        "status": status,
        "components": components,
        "architecture": "AKS + Redis + OpenAI"
    }

@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """Send a message and get response"""
    
    # Validate clients are initialized
    if not redis_client or not openai_client:
        raise HTTPException(status_code=503, detail="Services not ready")
    
    # Create or use session
    session_id = request.session_id or str(uuid.uuid4())
    
    try:
        # Get history from Redis
        history_key = f"chat:{session_id}"
        history_json = await redis_client.get(history_key)
        history = json.loads(history_json) if history_json else []
        
        # Add user message
        history.append({"role": "user", "content": request.message})
        
        # Call OpenAI
        messages = [
            {"role": "system", "content": "You are a helpful assistant."}
        ] + history[-10:]  # Last 10 messages
        
        response = await openai_client.chat.completions.create(
            model="gpt-4",
            messages=messages,
            max_tokens=500,
            timeout=30.0
        )
        
        ai_message = response.choices[0].message.content
        
        # Add AI response to history
        history.append({"role": "assistant", "content": ai_message})
        
        # Save to Redis (expires in 1 hour)
        await redis_client.setex(history_key, 3600, json.dumps(history))
        
        return ChatResponse(
            session_id=session_id,
            response=ai_message
        )
    
    except Exception as e:
        print(f"Error in chat: {str(e)}")
        raise HTTPException(status_code=500, detail="Chat service error")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)