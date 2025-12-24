from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

# Import auth functions from security/auth.py
from security.auth import verify_password, get_password_hash, create_access_token

# Import the get_current_username and get_current_user functions from services/users.py
from services.users import get_current_username, get_current_user

# Import the database session dependency
from db.database import get_db

# With the below import statement we import the User model and reference the username of a User by:
# User.username
from models.user import User

# To Avoid confusion / conflict with the names of Models we import the schemas Objects as:
# UserSchema, UserCreateSchema and TokenSchema
from schemas.user import User as UserSchema
from schemas.user import UserCreate as UserCreateSchema
from schemas.token import Token as TokenSchema

router_auth = APIRouter()

# 23-12-2025 - User Registration Endpoint disabled for Production
# @router_auth.post("/register", response_model=UserSchema, tags=["user"])
# Public Route
def register_user(user: UserCreateSchema, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)

    new_user = User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# User Login Endpoint which gets User Credentials and create JWT token if User is valid
# Public Route
@router_auth.post("/token", response_model=TokenSchema, tags=["user"])
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# Protected route that returns the current user's information
# Validation: 401 is returned if token is invalid and 404 if user not found
@router_auth.get("/users/me", response_model=UserSchema, tags=["user"])
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# Protected route that returns a message and the current user's Username 
# Validation: 401 is returned if token is invalid and 404 if user not found
@router_auth.get("/protected", tags=["user"])
async def protected_route(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello {current_user.username}, this is a protected route!"}

# Protected route that returns a message and the current user's Username using token directly
# Validation: 401 is returned if token is invalid 
@router_auth.get("/secure", tags=["user"])
def secure_endpoint(username: str = Depends(get_current_username)):
    return {"message": f"Hello {username}, you are authorized for this protected route!"}
