from fastapi import FastAPI

# Import the database engine
from db.database import engine

import models
import uvicorn

# Import the routes from routes/user.py
from routes.user import router_auth as router_auth_jwt

# Run the database migrations to create tables from the models
models.user.Base.metadata.create_all(bind=engine)

# Initialize the FastAPI app
app = FastAPI(

    title="Python + FastApi + PostgreSQL + Auth by JWT",
    description="23-12-2025 - FastAPI serving Auth by JWT using these credentials: testuser / admin",
    version="0.0.1",

    contact={
        "name": "Per Olsen",
        "url": "https://persteenolsen.netlify.app",
         },
)

# Include the routes from routes/user.py
app.include_router(router_auth_jwt)

# Run the application at Vercel
if __name__ == '__main__': #this indicates that this a script to be run
    uvicorn.run("main:app", host='0.0.0.0', port=8000, log_level="info", reload = True)
