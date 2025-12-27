from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm

# Import the database session dependency
from db.database import get_db
from sqlalchemy.orm import Session

# Import the get_current_username and get_current_user functions from services/users.py
from services.users import get_current_username, get_current_user
from services.users import get_all_users, get_access_token_for_login, do_register_user

# With the below import statement we import the User model and reference the username of a User by:
# User.username
from models.user import User

# To Avoid confusion / conflict with the names of Models we import the schemas Objects as:
# UserSchema, UserCreateSchema and TokenSchema
from schemas.user import User as UserSchema
from schemas.user import UserCreate as UserCreateSchema
from schemas.token import Token as TokenSchema

router_auth = APIRouter()

# Public route that returns access token and type if User credentials are valid
# 27-12-2025 - The endpoint needs to be /token for using the OpenAPI Autorize button
# Note: User Registration Endpoint disabled for Production
# @router_auth.post("/register", response_model=UserSchema, tags=["user"])
def register_user(user: UserCreateSchema, db: Session = Depends(get_db)):
    new_user = do_register_user(user, db)
    return new_user

# Public route that returns access token and type if User credentials are valid
# 27-12-2025 - The endpoint needs to be /token for using the OpenAPI Autorize button
@router_auth.post("/token", response_model=TokenSchema, tags=["user"])
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    return get_access_token_for_login(form_data ,db)
    

# Protected route that returns the current user's information
# Validation: 401 is returned if token is invalid and 404 if user not found
@router_auth.get("/users/me", response_model=UserSchema, tags=["user"])
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# Protected route that returns a message and the current user's Username using token directly
# Validation: 401 is returned if token is invalid 
@router_auth.get("/protected-route", tags=["user"])
def secure_endpoint(username: str = Depends(get_current_username)):
    return {"message": f"Hello {username}, you are authorized for this protected route!"}

# Protected route that returns all Users from the Database if the token is valid
# Validation: 401 is returned if token is invalid and 404 if no users found 
@router_auth.get("/get-all-users", response_model=list[UserSchema], tags=["user"])
def secure_endpoint(users: str = Depends(get_all_users)):
    return users