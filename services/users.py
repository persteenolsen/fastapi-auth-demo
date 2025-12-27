from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

# Import auth functions from security/auth.py
from security.auth import verify_password, verify_token, create_access_token, get_password_hash

# Import the database session dependency
from db.database import get_db

# With the below import statement we import the User model and reference the username of a User by:
# User.username
from models.user import User

from schemas.user import UserCreate as UserCreateSchema

# Define the OAuth2 scheme for token-based authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Note: The below to functions are placed in service/user.py for auth related functions in 
# order to separate concerns and make the code more modular
# Public route that registers a new User in the PostgreSQL Database
def do_register_user(user: UserCreateSchema, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = get_password_hash(user.password)
    
    # 25-12-2025 - Added Users Name
    new_user = User(username=user.username, name=user.name, email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user

# Public route that returns access token and type if User credentials are valid
# Note: This function uses Dependency Injection for form_data and db session
def get_access_token_for_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# Gets the Username of the current User from the JWT token
# Validate if the token is valid
# Validate if the User exist in the Database
# Return the current User with the information
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    username = verify_token(token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials! Try to Autorize ...",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# Gets the Username of the current User from the JWT token
# Validate if the token is valid
async def get_current_username(token: str = Depends(oauth2_scheme)):
    username = verify_token(token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The JWT Token is not valid or has expired! Try to Autorize ...",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return username

# Gets all Users from the PostgreSQL Database
# Validate if the token is valid
# Validate if there are any Users in the Database
# Returning all Users from the Database
async def get_all_users(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):

    # Validate Token
    username = verify_token(token)

    # If Token is not valid raise 401 Unauthorized with a custom message
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials! Try to Autorize ...",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get all Users from the Database
    users = db.query(User).all()

    # If no Users found raise 404 Not Found with a custom message
    if users is None:
        raise HTTPException(status_code=404, detail="No Users found")
    
    return users