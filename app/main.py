from fastapi import FastAPI

from app.errors import register_exception_handlers
from app.routers import preferences

app = FastAPI(
    title="Notification Preferences API",
    description="Multi-tenant notification preferences management",
    version="1.0.0",
)

register_exception_handlers(app)
app.include_router(preferences.router, prefix="/api/v1")


@app.get("/health")
def health_check():
    return {"status": "ok"}
