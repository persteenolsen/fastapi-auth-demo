from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import auth

from sqlalchemy.orm import Session
from database import get_db

# With the below import statement we import the User model and reference the username of a User by:
# User.username
from models.user import User

# To Avoid confusion / conflict with the names of Models we import the schemas Objects as:
# UserSchema, UserCreateSchema and TokenSchema
from schemas.user import User as UserSchema
from schemas.user import UserCreate as UserCreateSchema
from schemas.token import Token as TokenSchema

router_auth = APIRouter()

# Define the OAuth2 scheme for token-based authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Note: The below to functions could be placed in service/user.py for auth related functions in 
# order to separate concerns and make the code more modular
# Gets the Username of the current User from the JWT token
# Validate if the token is valid
async def get_current_username(token: str = Depends(oauth2_scheme)):
    username = auth.verify_token(token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The JWT Token is not valid or has expired! Try to Autorize ...",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return username

# Gets the Username of the current User from the JWT token
# Validate if the token is valid and if the User exists in the database
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    username = auth.verify_token(token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# 19-12-2025 - User Registration Endpoint disabled for Production
# @router_auth.post("/register", response_model=UserSchema)
def register_user(user: UserCreateSchema, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = auth.get_password_hash(user.password)

    new_user = User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# User Login Endpoint which gets User Credentials and create JWT token if User is valid
@router_auth.post("/token", response_model=TokenSchema)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# Protected route that returns the current user's information
# Validation: 401 is returned if token is invalid and 404 if user not found
@router_auth.get("/users/me", response_model=UserSchema)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# Protected route that returns a message and the current user's Username 
# Validation: 401 is returned if token is invalid and 404 if user not found
@router_auth.get("/protected", tags=["root"])
async def protected_route(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello {current_user.username}, this is a protected route!"}

# Protected route that returns a message and the current user's Username using token directly
# Validation: 401 is returned if token is invalid 
@router_auth.get("/secure", tags=["root"])
def secure_endpoint(username: str = Depends(get_current_username)):
    return {"message": f"Hello {username}, you are authorized for this protected route!"}

# Note: The below two routes are public and do not require authentication and could be placed
# in a separate router file for public routes
# Public root route that returns a message
@router_auth.get("/", tags=["root"])
async def read_root() -> dict:
    return {"message": "Welcome to FastAPI with Auth by JWT ..."}

# Public ping route that returns a pong message
@router_auth.get("/ping", tags=["root"])
async def read_root() -> dict:
    return {"message": "Pong ..."}