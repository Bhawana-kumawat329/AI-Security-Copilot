from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import analyze, threat, history, report , auth
from app.database.db import Base, engine
from app.models import scan, user

app = FastAPI(title="AI Security Copilot")
Base.metadata.create_all(bind=engine)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze.router)
app.include_router(threat.router)
app.include_router(history.router)
app.include_router(report.router)
app.include_router(auth.router)
@app.get("/")
def home():
    return {"message": "AI Security Copilot Backend Running"}
