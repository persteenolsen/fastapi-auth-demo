from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from database import engine, get_db
import models, schemas, auth
import uvicorn

# Run the database migrations
models.Base.metadata.create_all(bind=engine)

# Initialize the FastAPI app
app = FastAPI(

    title="Python + FastApi + PostgreSQL + Auth by JWT",
    description="20-12-2025 - FastAPI serving Auth by JWT using these credentials: testuser / admin",
    version="0.0.1",

    contact={
        "name": "Per Olsen",
        "url": "https://persteenolsen.netlify.app",
         },
)

# Define the OAuth2 scheme for token-based authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 19-12-2025 - User Registration Endpoint disabled at Production
# @app.post("/register", response_model=schemas.User)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = auth.get_password_hash(user.password)
    new_user = models.User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# User Login Endpoint which gets User Credentials and create JWT token if User is valid
@app.post("/token", response_model=schemas.Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# Function that validates if the current User is Authenticated to the requested route 
# Gets the Username of the current User from the JWT token and validate if the User exists in the DB 
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    username = auth.verify_token(token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# Public root route that returns a message
@app.get("/", tags=["root"])
async def read_root() -> dict:
    return {"message": "Welcome to FastAPI with Auth by JWT ..."}

# Protected route that returns the current user's information
# Validation: 401 is returned if token is invalid and 404 if user not found
@app.get("/users/me", response_model=schemas.User)
async def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user

# Protected route that returns a message and the current user's Username 
# Validation: 401 is returned if token is invalid and 404 if user not found
@app.get("/protected", tags=["root"])
async def protected_route(current_user: models.User = Depends(get_current_user)):
    return {"message": f"Hello {current_user.username}, this is a protected route!"}

# Protected route that returns a message and the current user's Username using token directly
# Validation: 401 is returned if token is invalid 
@app.get("/secure", tags=["root"])
def secure_endpoint(token: str = Depends(oauth2_scheme)):
    username = auth.verify_token(token)
    return {"message": f"Hello {username}, you are authorized for this protected route!"}


# Run the application at Vercel
if __name__ == '__main__': #this indicates that this a script to be run
    uvicorn.run("main:app", host='0.0.0.0', port=8000, log_level="info", reload = True)
