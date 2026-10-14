# vaultmind_auth_routes.py
# Login and Me endpoints for VaultMind authentication

from fastapi import APIRouter, HTTPException, Depends, Request, Response, status
from pydantic import BaseModel

from core.auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    TokenData,
    hash_password,
    get_user_from_supabase,
)
from core.db_connections import supabase_db

router = APIRouter(prefix="/auth", tags=["Authentication"])

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# REQUEST / RESPONSE SCHEMAS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class LoginRequest(BaseModel):
    email:    str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type:   str
    user:         dict          # { email, role, name }

class SignupRequest(BaseModel):
    email:    str  # mapped to emp_id
    name:     str
    password: str
    role:     str  # 'analyst' or 'auditor'

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# POST /api/auth/signup
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@router.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup(payload: SignupRequest):
    """
    Register a new bank employee / analyst.
    Hashes password and inserts to bank_employees in Supabase.
    """
    if not payload.email or not payload.password or not payload.name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required fields."
        )

    # Check if user already exists
    existing_user = get_user_from_supabase(payload.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Employee ID / Email already registered."
        )

    if payload.role not in ["analyst", "auditor"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be 'analyst' or 'auditor'."
        )

    hashed_pw = hash_password(payload.password)

    try:
        response = supabase_db.table("bank_employees").insert({
            "emp_id": payload.email,
            "name": payload.name,
            "password": hashed_pw,
            "role": payload.role
        }).execute()

        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to register user."
            )

        return {
            "message": "User registered successfully",
            "user": {
                "email": payload.email,
                "role": payload.role,
                "name": payload.name
            }
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error during registration: {str(e)}"
        )

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# POST /api/auth/login
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
failed_login_attempts = {}

@router.post("/login", response_model=LoginResponse)
async def login(request: Request, payload: LoginRequest):
    """
    Authenticate user with email + password.
    Returns a JWT access token on success.
    Rate limited to 5 requests/minute per IP (applied in main.py).
    """
    ip = request.client.host if request.client else "unknown"
    if failed_login_attempts.get(ip, 0) >= 5:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Account locked temporarily."
        )

    user = authenticate_user(payload.email, payload.password)

    if not user:
        failed_login_attempts[ip] = failed_login_attempts.get(ip, 0) + 1
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    failed_login_attempts[ip] = 0

    token = create_access_token({
        "sub":  user["email"],
        "role": user["role"],
        "name": user["name"],
    })

    from fastapi.responses import JSONResponse
    response = JSONResponse(content={
        "access_token": token,
        "token_type":   "bearer",
        "user": {
            "email": user["email"],
            "role":  user["role"],
            "name":  user["name"],
        },
    })

    # We set the cookie as httponly, secure, samesite=lax
    response.set_cookie(
        key="vm_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=3600  # 1 hour
    )

    return response

@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("vm_token")
    return {"message": "Logged out successfully"}

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# GET /api/auth/me
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@router.get("/me")
async def get_me(current_user: TokenData = Depends(get_current_user)):
    """
    Returns current user info decoded from the JWT token.
    Used by frontend on page refresh to verify token is still valid.
    """
    return {
        "email": current_user.email,
        "role":  current_user.role,
        "name":  current_user.name,
    }
