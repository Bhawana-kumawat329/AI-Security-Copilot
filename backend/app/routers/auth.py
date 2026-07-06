from fastapi import APIRouter
from pydantic import BaseModel, EmailStr
from app.database.db import SessionLocal
from app.models.user import User
from app.services.auth_service import hash_password, verify_password, create_access_token

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

@router.post("/signup")
def signup(request: SignupRequest):
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == request.email).first()
        if existing:
            return {"success": False, "message": "Email already registered"}

        user = User(
            name=request.name,
            email=request.email,
            password_hash=hash_password(request.password)
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        return {
            "success": True,
            "message": "Signup successful",
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role
            }
        }
    finally:
        db.close()

@router.post("/login")
def login(request: LoginRequest):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == request.email).first()

        if not user or not verify_password(request.password, user.password_hash):
            return {"success": False, "message": "Invalid email or password"}

        token = create_access_token({
            "sub": user.email,
            "user_id": user.id,
            "role": user.role
        })

        return {
            "success": True,
            "message": "Login successful",
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role
            }
        }
    finally:
        db.close()
