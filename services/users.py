from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

# import auth functions from security/auth.py
from security.auth import verify_token

# Import the database session dependency
from db.database import get_db

# With the below import statement we import the User model and reference the username of a User by:
# User.username
from models.user import User

# Define the OAuth2 scheme for token-based authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Note: The below to functions are placed in service/user.py for auth related functions in 
# order to separate concerns and make the code more modular

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