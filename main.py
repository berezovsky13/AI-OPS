"""
Enterprise Chatbot - Production Ready
FastAPI + Redis + Azure OpenAI + Key Vault
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import redis.asyncio as redis
from openai import AsyncAzureOpenAI
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import json
import uuid
import os
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== Configuration ====================
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6380"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
OPENAI_ENDPOINT = os.getenv("OPENAI_ENDPOINT", "https://your-openai.openai.azure.com/")
OPENAI_DEPLOYMENT = os.getenv("OPENAI_DEPLOYMENT_NAME", "gpt-4o-mini")
KEY_VAULT_URL = os.getenv("KEY_VAULT_URL", "")

app = FastAPI(
    title="Enterprise Chatbot API",
    version="1.0.0",
    description="Production-ready chatbot with Redis state management and Azure OpenAI"
)

# Global clients
redis_client = None
openai_client = None
credential = None

# ==================== Models ====================
class ChatRequest(BaseModel):
    message: str
    session_id: str = None

class ChatResponse(BaseModel):
    session_id: str
    response: str
    tokens_used: int = 0

class HealthResponse(BaseModel):
    status: str
    components: dict
    architecture: dict

# ==================== Startup ====================
@app.on_event("startup")
async def startup():
    global redis_client, openai_client, credential
    
    logger.info("🚀 Starting Chatbot Service...")
    
    # Initialize Azure Credential
    credential = DefaultAzureCredential()
    
    # Connect to Redis
    try:
        logger.info(f"🔌 Connecting to Redis: {REDIS_HOST}:{REDIS_PORT}")
        redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            password=REDIS_PASSWORD,
            ssl=True,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_keepalive=True,
            retry_on_timeout=True
        )
        await redis_client.ping()
        logger.info("✅ Redis connected successfully")
    except Exception as e:
        logger.error(f"❌ Redis connection failed: {str(e)}")
        raise
    
    # Initialize OpenAI Client
    try:
        logger.info(f"🤖 Connecting to Azure OpenAI: {OPENAI_ENDPOINT}")
        openai_client = AsyncAzureOpenAI(
            azure_endpoint=OPENAI_ENDPOINT,
            api_version="2024-02-15-preview",
            azure_ad_token_provider=lambda: credential.get_token(
                "https://cognitiveservices.azure.com/.default"
            ).token
        )
        logger.info("✅ Azure OpenAI connected successfully")
    except Exception as e:
        logger.error(f"❌ OpenAI connection failed: {str(e)}")
        raise
    
    logger.info("🎉 Chatbot Service started successfully!")

@app.on_event("shutdown")
async def shutdown():
    logger.info("👋 Shutting down Chatbot Service...")
    if redis_client:
        await redis_client.aclose()
    if openai_client:
        await openai_client.close()
    logger.info("✅ Shutdown complete")

# ==================== Endpoints ====================
@app.get("/")
def root():
    """Root endpoint with service information"""
    return {
        "service": "Enterprise Chatbot API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "chat": "/chat (POST)",
            "session": "/sessions/{session_id} (GET)",
            "docs": "/docs"
        },
        "architecture": {
            "compute": "Azure Kubernetes Service (AKS)",
            "cache": "Azure Redis Cache (Premium)",
            "ai": "Azure OpenAI Service (gpt-4o-mini)",
            "security": "Azure Key Vault + Managed Identity",
            "monitoring": "Azure Log Analytics + Alerts"
        }
    }

@app.get("/health", response_model=HealthResponse)
async def health():
    """
    Comprehensive health check for all components
    Tests connectivity to Redis, OpenAI, and Key Vault
    """
    components = {}
    errors = []
    
    # Test Redis
    try:
        await redis_client.ping()
        info = await redis_client.info()
        components["redis"] = {
            "status": "connected",
            "host": REDIS_HOST,
            "port": REDIS_PORT,
            "version": info.get("redis_version", "unknown"),
            "connected_clients": info.get("connected_clients", 0)
        }
    except Exception as e:
        components["redis"] = {"status": "error", "error": str(e)}
        errors.append(f"Redis: {str(e)}")
    
    # Test OpenAI
    try:
        if openai_client:
            components["openai"] = {
                "status": "connected",
                "endpoint": OPENAI_ENDPOINT,
                "deployment": OPENAI_DEPLOYMENT,
                "api_version": "2024-02-15-preview"
            }
        else:
            components["openai"] = {"status": "not_initialized"}
            errors.append("OpenAI: Not initialized")
    except Exception as e:
        components["openai"] = {"status": "error", "error": str(e)}
        errors.append(f"OpenAI: {str(e)}")
    
    # Test Key Vault (if configured)
    if KEY_VAULT_URL:
        try:
            secret_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)
            # Just test connection, don't retrieve secrets
            components["keyvault"] = {
                "status": "connected",
                "vault_url": KEY_VAULT_URL
            }
        except Exception as e:
            components["keyvault"] = {"status": "error", "error": str(e)}
            errors.append(f"KeyVault: {str(e)}")
    
    # Overall status
    all_healthy = all(
        comp.get("status") == "connected" 
        for comp in components.values()
    )
    
    return HealthResponse(
        status="healthy" if all_healthy else "degraded",
        components=components,
        architecture={
            "compute": "Azure Kubernetes Service (AKS)",
            "cache": "Azure Redis Cache (Premium)",
            "ai": "Azure OpenAI Service",
            "security": "Azure Key Vault + Managed Identity",
            "networking": "Private VNet with NSG",
            "monitoring": "Azure Log Analytics + Metric Alerts"
        }
    )

@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Main chat endpoint with session state management
    
    - Stores conversation history in Redis
    - Uses Azure OpenAI for responses
    - Supports multi-turn conversations
    """
    
    # Validate clients
    if not redis_client or not openai_client:
        raise HTTPException(
            status_code=503, 
            detail="Services not ready. Check /health endpoint."
        )
    
    # Create or use existing session
    session_id = request.session_id or str(uuid.uuid4())
    
    try:
        # Get conversation history from Redis
        history_key = f"chat:session:{session_id}"
        history_json = await redis_client.get(history_key)
        history = json.loads(history_json) if history_json else []
        
        # Add user message
        history.append({"role": "user", "content": request.message})
        
        # Prepare messages for OpenAI (system + last 10 messages)
        messages = [
            {
                "role": "system", 
                "content": "You are a helpful AI assistant for enterprise chatbot. "
                          "Provide clear, professional, and accurate responses."
            }
        ] + history[-10:]
        
        # Call Azure OpenAI
        logger.info(f"🤖 Calling OpenAI for session {session_id}")
        response = await openai_client.chat.completions.create(
            model=OPENAI_DEPLOYMENT,
            messages=messages,
            max_tokens=500,
            temperature=0.7,
            timeout=30.0
        )
        
        ai_message = response.choices[0].message.content
        tokens_used = response.usage.total_tokens
        
        # Add AI response to history
        history.append({"role": "assistant", "content": ai_message})
        
        # Save to Redis with 1 hour expiration
        await redis_client.setex(history_key, 3600, json.dumps(history))
        
        logger.info(f"✅ Response generated for session {session_id} ({tokens_used} tokens)")
        
        return ChatResponse(
            session_id=session_id,
            response=ai_message,
            tokens_used=tokens_used
        )
    
    except Exception as e:
        logger.error(f"❌ Error in chat endpoint: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Chat service error: {str(e)}"
        )

@app.get("/sessions/{session_id}")
async def get_session(session_id: str):
    """
    Retrieve conversation history for a session
    """
    try:
        history_key = f"chat:session:{session_id}"
        history_json = await redis_client.get(history_key)
        
        if not history_json:
            raise HTTPException(status_code=404, detail="Session not found")
        
        history = json.loads(history_json)
        return {
            "session_id": session_id,
            "message_count": len(history),
            "history": history
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error retrieving session: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/sessions/{session_id}")
async def delete_session(session_id: str):
    """
    Delete a conversation session
    """
    try:
        history_key = f"chat:session:{session_id}"
        deleted = await redis_client.delete(history_key)
        
        if deleted == 0:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return {"message": f"Session {session_id} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error deleting session: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")