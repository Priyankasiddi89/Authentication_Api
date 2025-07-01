import os
from fastapi import FastAPI, HTTPException, Depends, status, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from pymongo import MongoClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from dotenv import load_dotenv
from datetime import datetime, timedelta
from typing import Optional
from fastapi.encoders import jsonable_encoder
from bson import ObjectId

# Load environment variables
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client['virtual_Presenz']
users_collection = db['mobile_users']

SECRET_KEY = os.getenv("SECRET_KEY", "secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

USER_STRUCTURE = {
    "End User": ["Head of House", "Family member"],
    "Service Provider": ["Admin", "Employee", "Supervisor"],
    "Platform Provider": ["Admin", "Employee", "Service Desk"]
}

class UserRegister(BaseModel):
    username: str
    password: str
    user_type: str
    role: str

class Token(BaseModel):
    access_token: str
    token_type: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(username: str):
    return users_collection.find_one({"username": username})

router = APIRouter(prefix="/mobile_api/auth")

@router.post("/register", status_code=201)
def register(user: UserRegister):
    if user.user_type not in USER_STRUCTURE:
        raise HTTPException(status_code=400, detail="Invalid user type")
    if user.role not in USER_STRUCTURE[user.user_type]:
        raise HTTPException(status_code=400, detail="Invalid role for user type")
    if get_user(user.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    users_collection.insert_one({
        "username": user.username,
        "password": hashed_password,
        "user_type": user.user_type,
        "role": user.role,
        "is_active": True  # Only visible in DB
    })
    return {"msg": "User registered successfully"}

@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={
        "sub": user["username"],
        "user_type": user["user_type"],
        "role": user["role"]
    })
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/logout")
def logout(token: str = Depends(oauth2_scheme)):
    # Stateless JWT: logout is handled client-side by deleting the token
    return {"msg": "Logout successful (client should delete token)"}

# Utility for role-based access
from fastapi import Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        user_type = payload.get("user_type")
        role = payload.get("role")
        if not isinstance(username, str) or not isinstance(user_type, str) or not isinstance(role, str):
            raise credentials_exception
        return {"username": username, "user_type": user_type, "role": role}
    except JWTError:
        raise credentials_exception

def require_role(allowed_user_types=None, allowed_roles=None):
    def role_checker(current_user=Depends(get_current_user)):
        if allowed_user_types and current_user["user_type"] not in allowed_user_types:
            raise HTTPException(status_code=403, detail="User type not allowed")
        if allowed_roles and current_user["role"] not in allowed_roles:
            raise HTTPException(status_code=403, detail="Role not allowed")
        return current_user
    return role_checker

@router.get("/protected-endpoint")
def protected_endpoint(current_user=Depends(require_role(allowed_user_types=["Service Provider"], allowed_roles=["Admin"]))):
    return {"msg": f"Hello, {current_user['username']}! You are a {current_user['role']} in {current_user['user_type']}."}

@router.get("/current_user")
def get_current_user_info(current_user=Depends(get_current_user)):
    user = users_collection.find_one({"username": current_user["username"]})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.pop("_id", None)
    user.pop("password", None)
    return user

@router.get("/active_users")
def get_active_users(current_user=Depends(get_current_user)):
    users = list(users_collection.find({"is_active": True}))
    for user in users:
        user.pop("_id", None)
        user.pop("password", None)
    return users

@router.get("/all_users")
def get_all_users(current_user=Depends(get_current_user)):
    users = list(users_collection.find())
    for user in users:
        user.pop("_id", None)
        user.pop("password", None)
    return users

app.include_router(router) 