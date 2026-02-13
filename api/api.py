from fastapi import FastAPI

# Import the database engine
from db.database import engine

import models

from fastapi.middleware.cors import CORSMiddleware

# Import the routes from routes/user.py
from routes.user import router_auth as router_auth_jwt

# Import the routes from routes/simple.py
from routes.simple import router_simple as router_simple_one

# Run the database migrations to create tables from the models
models.user.Base.metadata.create_all(bind=engine)

# Initialize the FastAPI app
app = FastAPI(

    title="Python + FastApi + PostgreSQL + SQLAlchemy + Alembic + JWT Auth",
    description="13-02-2026 - FastAPI serving JWT Authentication using these credentials: testuser / admin",
    version="0.0.1",

    contact={
        "name": "Per Olsen",
        "url": "https://persteenolsen.netlify.app",
         },
)

# Set up CORS middleware
origins = [

    # Not sure if this is needed, but adding just in case
    "https://fastapi-auth-demo.vercel.app",

    # The domain name of the Vue 3 SPA Client
    "https://vue.fastapi.jwt.auth.client.persteenolsen.com",
     
    # Allow my local Vue SPA
    "http://localhost:3000"
    
]


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include the routes from routes/user.py
app.include_router(router_auth_jwt)

# Include the routes from routes/simple.py
app.include_router(router_simple_one)

