from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, validator
from typing import Optional, List, Dict
import os
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
import logging
from dotenv import load_dotenv
import traceback
from supabase import create_client, Client

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# Supabase imports


# Initialize FastAPI app
app = FastAPI(
    title="Jeet Enterprises Authentication API",
    description="Backend API for user authentication and subscription management",
    version="1.0.0"
)

# PRODUCTION: Remove static file serving - frontend will be on Netlify
# No static file mounts needed in production

# PRODUCTION: Remove HTML serving routes - frontend handles routing
# No FileResponse routes needed

# PRODUCTION: Update CORS for your deployed frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        # Your production frontend URL
        "https://jeetenterprises.netlify.app",
        "https://*.netlify.app",  # Allow Netlify preview deployments
        
        # Keep localhost for development
        "http://localhost:3000", 
        "http://127.0.0.1:3000", 
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Environment variables validation
def validate_env_vars():
    required_vars = ["SUPABASE_URL", "SUPABASE_KEY", "JWT_SECRET"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        raise ValueError(f"Missing required environment variables: {missing_vars}")

# Validate environment on startup
validate_env_vars()

# Environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# PRODUCTION: Use environment variable for frontend URL
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://jeetenterprises.netlify.app")

# OAuth redirect URLs for Supabase
OAUTH_REDIRECT_URL = f"{FRONTEND_URL}/#auth/callback"

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Add admin client for admin operations
supabase_admin: Client = None
if SUPABASE_SERVICE_KEY:
    try:
        supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        logger.info("✅ Supabase admin client initialized")
    except Exception as e:
        logger.warning(f"⚠️ Supabase admin client failed: {e}")
else:
    logger.warning("⚠️ SUPABASE_SERVICE_KEY not provided - using fallback")

# Security
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Logging


# API ROOT - Just return API info, no HTML
@app.get("/")
async def api_root():
    """API root endpoint - returns API information"""
    return {
        "api": "Jeet Enterprises Authentication API",
        "version": "1.0.0",
        "status": "running",
        "frontend_url": FRONTEND_URL,
        "oauth_redirect_url": OAUTH_REDIRECT_URL,
        "endpoints": {
            "health": "/health",
            "auth_login": "/auth/login",
            "auth_signup": "/auth/signup", 
            "oauth_google": "/auth/oauth/google",
            "oauth_github": "/auth/oauth/github",
            "oauth_exchange": "/auth/oauth/exchange",
            "profile": "/profile/",
            "debug": "/debug/supabase"
        }
    }

# Pydantic Models
class UserSignup(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    phone: str
    newsletter_subscription: Optional[bool] = False

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v

    @validator('full_name')
    def validate_full_name(cls, v):
        if len(v.strip()) < 2:
            raise ValueError('Full name must be at least 2 characters long')
        return v.strip()

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class PasswordReset(BaseModel):
    email: EmailStr

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

    @validator('new_password')
    def validate_new_password(cls, v):
        if len(v) < 8:
            raise ValueError('New password must be at least 8 characters long')
        return v

class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    phone: Optional[str] = None

class SubscriptionUpdate(BaseModel):
    subscription_type: str

    @validator('subscription_type')
    def validate_subscription(cls, v):
        if v not in ['free', 'premium', 'pro']:
            raise ValueError('Invalid subscription type')
        return v

class OAuthTokenExchange(BaseModel):
    access_token: str
    refresh_token: str

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    phone: str
    subscription: str
    provider: Optional[str] = None
    avatar_url: Optional[str] = None
    created_at: datetime

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class OAuthUrlResponse(BaseModel):
    url: str
    provider: str

# Helper Functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = verify_token(token)
    user_id = payload.get("sub")
    
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    
    try:
        response = supabase.table('profiles').select('*').eq('id', user_id).execute()
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        user_profile = response.data[0]
        try:
            if supabase_admin:
                auth_user = supabase_admin.auth.admin.get_user_by_id(user_id)
                if auth_user and auth_user.user:
                    user_profile["email"] = auth_user.user.email
                else:
                    user_profile["email"] = payload.get("email", "")
            else:
                user_profile["email"] = payload.get("email", "")
        except Exception as e:
            logger.warning(f"⚠️ Admin call failed, using fallback: {e}")
            user_profile["email"] = payload.get("email", "")
            
        return user_profile
    except Exception as e:
        logger.error(f"Error fetching user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error fetching user data"
        )

# Authentication Routes
@app.post("/auth/signup", response_model=dict)
async def signup(user_data: UserSignup):
    """Create a new user account with email and password"""
    try:
        existing_user = supabase.table('profiles').select('id').eq('email', user_data.email).execute()
        if existing_user.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        auth_response = supabase.auth.sign_up({
            "email": user_data.email,
            "password": user_data.password,
            "options": {
                "data": {
                    "full_name": user_data.full_name,
                    "phone": user_data.phone,
                    "newsletter_subscription": user_data.newsletter_subscription
                }
            }
        })
        
        if not auth_response.user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to create user account"
            )
        
        return {
            "message": "User created successfully. Please check your email for verification.",
            "user_id": auth_response.user.id,
            "email_confirmed": auth_response.user.email_confirmed_at is not None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Signup error: {e}")
        if "already registered" in str(e).lower() or "duplicate" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during signup"
        )

@app.post("/auth/login", response_model=TokenResponse)
async def login(user_credentials: UserLogin):
    """Login with email and password"""
    try:
        auth_response = supabase.auth.sign_in_with_password({
            "email": user_credentials.email,
            "password": user_credentials.password
        })
        
        if not auth_response.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        user_id = auth_response.user.id
        
        profile_response = supabase.table('profiles').select('*').eq('id', user_id).execute()
        
        if not profile_response.data:
            profile_data = {
                "id": user_id,
                "full_name": auth_response.user.user_metadata.get("full_name", ""),
                "phone": auth_response.user.user_metadata.get("phone", ""),
                "subscription": "free"
            }
            profile_response = supabase.table('profiles').insert(profile_data).execute()
            if not profile_response.data:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to create user profile"
                )
        
        profile = profile_response.data[0]
        
        access_token = create_access_token(data={"sub": user_id, "email": user_credentials.email})
        
        user_response = UserResponse(
            id=profile["id"],
            email=auth_response.user.email,
            full_name=profile["full_name"] or "",
            phone=profile["phone"] or "",
            subscription=profile["subscription"],
            provider=profile.get("provider"),
            avatar_url=profile.get("avatar_url"),
            created_at=profile["created_at"]
        )
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            user=user_response
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

# OAuth Routes
@app.get("/auth/oauth/google", response_model=OAuthUrlResponse)
async def get_google_oauth():
    """Get Google OAuth URL from Supabase"""
    try:
        oauth_url = f"{SUPABASE_URL}/auth/v1/authorize?provider=google&redirect_to={OAUTH_REDIRECT_URL}"
        logger.info(f"Generated Google OAuth URL: {oauth_url}")
        return OAuthUrlResponse(
            url=oauth_url,
            provider="google"
        )
    except Exception as e:
        logger.error(f"Google OAuth URL error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate Google OAuth URL"
        )

@app.get("/auth/oauth/github", response_model=OAuthUrlResponse)
async def get_github_oauth():
    """Get GitHub OAuth URL from Supabase"""
    try:
        oauth_url = f"{SUPABASE_URL}/auth/v1/authorize?provider=github&redirect_to={OAUTH_REDIRECT_URL}"
        logger.info(f"Generated GitHub OAuth URL: {oauth_url}")
        return OAuthUrlResponse(
            url=oauth_url,
            provider="github"
        )
    except Exception as e:
        logger.error(f"GitHub OAuth URL error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate GitHub OAuth URL"
        )

@app.get("/auth/oauth/linkedin", response_model=OAuthUrlResponse)
async def get_linkedin_oauth():
    """Get LinkedIn OAuth URL from Supabase"""
    try:
        oauth_url = f"{SUPABASE_URL}/auth/v1/authorize?provider=linkedin_oidc&redirect_to={OAUTH_REDIRECT_URL}"
        logger.info(f"Generated LinkedIn OAuth URL: {oauth_url}")
        return OAuthUrlResponse(
            url=oauth_url,
            provider="linkedin"
        )
    except Exception as e:
        logger.error(f"LinkedIn OAuth URL error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate LinkedIn OAuth URL"
        )

@app.post("/auth/oauth/exchange", response_model=TokenResponse)
async def exchange_oauth_tokens(token_data: OAuthTokenExchange):
    """Exchange OAuth tokens received from Supabase callback for user session"""
    logger.info("🔄 Starting OAuth token exchange")
    logger.info(f"Received tokens - Access: {len(token_data.access_token)} chars, Refresh: {len(token_data.refresh_token)} chars")
    
    try:
        if not token_data.access_token or len(token_data.access_token) < 10:
            logger.error("Invalid access token format")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid access token format"
            )
            
        if not token_data.refresh_token or len(token_data.refresh_token) < 10:
            logger.error("Invalid refresh token format")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid refresh token format"
            )

        logger.info("✅ Token format validation passed")
        
        try:
            logger.info("Setting Supabase session with tokens...")
            auth_response = supabase.auth.set_session(
                token_data.access_token, 
                token_data.refresh_token
            )
            logger.info(f"Supabase session response: {type(auth_response)}")
            
        except Exception as session_error:
            logger.error(f"Supabase session error: {session_error}")
            try:
                logger.info("Trying alternative session method...")
                user_response = supabase.auth.get_user(token_data.access_token)
                auth_response = user_response
                logger.info("✅ Alternative session method worked")
            except Exception as alt_error:
                logger.error(f"Alternative session method failed: {alt_error}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Failed to validate OAuth tokens: {str(session_error)}"
                )
        
        if not auth_response.user:
            logger.error("No user found in auth response")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid OAuth tokens - no user found"
            )
        
        user_id = auth_response.user.id
        user_email = auth_response.user.email
        logger.info(f"✅ User authenticated: {user_id} ({user_email})")
        
        logger.info("Fetching user profile...")
        profile_response = supabase.table('profiles').select('*').eq('id', user_id).execute()
        
        if not profile_response.data:
            logger.info("Creating new user profile...")
            user_metadata = auth_response.user.user_metadata or {}
            
            full_name = (
                user_metadata.get("full_name") or 
                user_metadata.get("name") or 
                user_metadata.get("display_name") or
                f"{user_metadata.get('given_name', '')} {user_metadata.get('family_name', '')}".strip() or
                user_email.split('@')[0]
            )
            
            avatar_url = (
                user_metadata.get("avatar_url") or 
                user_metadata.get("picture") or
                user_metadata.get("photo") or
                None
            )
            
            profile_data = {
                "id": user_id,
                "full_name": full_name,
                "phone": user_metadata.get("phone", ""),
                "subscription": "free",
                "provider": user_metadata.get("provider", "oauth"),
                "avatar_url": avatar_url
            }
            
            logger.info(f"Creating profile with data: {profile_data}")
            
            try:
                profile_response = supabase.table('profiles').insert(profile_data).execute()
                logger.info("✅ Profile created successfully")
            except Exception as profile_error:
                logger.error(f"Profile creation error: {profile_error}")
                profile_data = {
                    "id": user_id,
                    "full_name": full_name,
                    "subscription": "free"
                }
                try:
                    profile_response = supabase.table('profiles').insert(profile_data).execute()
                    logger.info("✅ Minimal profile created")
                except Exception as minimal_error:
                    logger.error(f"Minimal profile creation failed: {minimal_error}")
                    profile_response.data = [profile_data]
        
        if not profile_response.data:
            logger.error("Failed to get or create profile")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user profile"
            )
        
        profile = profile_response.data[0]
        logger.info(f"✅ Profile retrieved: {profile}")
        
        jwt_token = create_access_token(data={
            "sub": user_id, 
            "email": user_email,
            "provider": "oauth"
        })
        logger.info("✅ JWT token created")
        
        user_response = UserResponse(
            id=profile["id"],
            email=user_email,
            full_name=profile.get("full_name", ""),
            phone=profile.get("phone", ""),
            subscription=profile.get("subscription", "free"),
            provider=profile.get("provider"),
            avatar_url=profile.get("avatar_url"),
            created_at=profile.get("created_at", datetime.utcnow())
        )
        
        token_response = TokenResponse(
            access_token=jwt_token,
            token_type="bearer",
            user=user_response
        )
        
        logger.info("✅ OAuth token exchange completed successfully")
        return token_response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ OAuth token exchange error: {e}")
        logger.error(f"Error type: {type(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to exchange OAuth tokens: {str(e)}"
        )

@app.post("/auth/reset-password")
async def reset_password(reset_data: PasswordReset):
    """Send password reset email"""
    try:
        response = supabase.auth.reset_password_email(
            reset_data.email,
            {
                "redirect_to": f"{FRONTEND_URL}/reset-password"
            }
        )
        
        return {"message": "Password reset email sent successfully"}
        
    except Exception as e:
        logger.error(f"Password reset error: {e}")
        return {"message": "If the email exists, a reset link will be sent"}

@app.post("/auth/change-password")
async def change_password(
    password_data: PasswordChange,
    current_user: dict = Depends(get_current_user)
):
    """Change user password"""
    try:
        try:
            auth_response = supabase.auth.sign_in_with_password({
                "email": current_user.get("email"),
                "password": password_data.current_password
            })
            if not auth_response.user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Current password is incorrect"
                )
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )

        update_response = (supabase_admin or supabase).auth.admin.update_user_by_id(
            current_user["id"],
            {
                "password": password_data.new_password
            }
        )
        
        if not update_response.user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update password"
            )
        
        return {"message": "Password updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password"
        )

@app.post("/auth/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Logout current user - Fixed to handle admin API gracefully"""
    try:
        logger.info(f"Logging out user: {current_user['id']}")
        supabase.auth.sign_out()
        logger.info("✅ User logged out successfully")
        return {"message": "Successfully logged out"}
    except Exception as e:
        logger.warning(f"⚠️ Logout warning (non-critical): {e}")
        return {"message": "Logged out"}

# Profile Routes
@app.get("/profile/", response_model=UserResponse)
async def get_profile(current_user: dict = Depends(get_current_user)):
    """Get current user profile"""
    try:
        user_response = UserResponse(
            id=current_user["id"],
            email=current_user.get("email", ""),
            full_name=current_user["full_name"] or "",
            phone=current_user["phone"] or "",
            subscription=current_user["subscription"],
            provider=current_user.get("provider"),
            avatar_url=current_user.get("avatar_url"),
            created_at=current_user["created_at"]
        )
        
        return user_response
        
    except Exception as e:
        logger.error(f"Get profile error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch user profile"
        )

@app.put("/profile/update", response_model=UserResponse)
async def update_profile(
    profile_data: ProfileUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update user profile"""
    try:
        update_data = {}
        if profile_data.full_name is not None:
            update_data["full_name"] = profile_data.full_name
        if profile_data.phone is not None:
            update_data["phone"] = profile_data.phone
        
        if not update_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No data provided for update"
            )
        
        response = supabase.table('profiles').update(update_data).eq('id', current_user["id"]).execute()
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update profile"
            )
        
        updated_profile = response.data[0]
        
        user_response = UserResponse(
            id=updated_profile["id"],
            email=current_user.get("email", ""),
            full_name=updated_profile["full_name"] or "",
            phone=updated_profile["phone"] or "",
            subscription=updated_profile["subscription"],
            provider=updated_profile.get("provider"),
            avatar_url=updated_profile.get("avatar_url"),
            created_at=updated_profile["created_at"]
        )
        
        return user_response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update profile error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update profile"
        )

# Debug endpoints
@app.get("/debug/supabase")
async def debug_supabase():
    """Debug Supabase connection and configuration"""
    try:
        health_check = supabase.table('profiles').select('count').limit(1).execute()
        
        try:
            users = supabase.auth.admin.list_users(page=1, per_page=1)
            auth_admin_status = "OK"
        except Exception as e:
            auth_admin_status = f"ERROR: {str(e)}"
        
        return {
            "supabase_url": SUPABASE_URL[:50] + "..." if SUPABASE_URL else "MISSING",
            "supabase_key_length": len(SUPABASE_KEY) if SUPABASE_KEY else 0,
            "supabase_service_key_length": len(SUPABASE_SERVICE_KEY) if SUPABASE_SERVICE_KEY else 0,
            "database_connection": "OK" if health_check else "ERROR",
            "auth_admin_access": auth_admin_status,
            "oauth_redirect_url": OAUTH_REDIRECT_URL,
            "profiles_table_accessible": bool(health_check.data) if health_check else False,
            "environment": {
                "frontend_url": FRONTEND_URL,
                "jwt_secret_set": bool(JWT_SECRET)
            }
        }
    except Exception as e:
        return {
            "error": str(e),
            "status": "FAILED",
            "traceback": traceback.format_exc()
        }

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        response = supabase.table('profiles').select('count').limit(1).execute()
        return {
            "status": "healthy", 
            "timestamp": datetime.utcnow(),
            "database": "connected",
            "version": "1.0.0",
            "oauth_redirect_url": OAUTH_REDIRECT_URL,
            "frontend_url": FRONTEND_URL
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow(),
            "database": "disconnected",
            "error": str(e)
        }

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={"detail": "Endpoint not found"}
    )

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Application startup"""
    logger.info("Jeet Enterprises API started successfully")
    logger.info(f"Supabase URL: {SUPABASE_URL}")
    logger.info(f"Frontend URL: {FRONTEND_URL}")
    logger.info(f"OAuth Redirect URL: {OAUTH_REDIRECT_URL}")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Jeet Enterprises API shutting down")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000, 
        reload=True,
        log_level="info"
    )