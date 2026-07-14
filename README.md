# 🔐 JWT Authentication API (FastAPI + PostgreSQL)

A REST API built with FastAPI that demonstrates user authentication using JWT access tokens for Single Page Applications (SPAs).

This project was created to learn modern backend architecture, authentication flows, database migrations, manuel tests, and deployment practices using Python.

**Last updated:**
- 14-07-2026

**Python version:**
- 3.12

---

## ✨ Features

- User registration and login
- JWT-based authentication (access tokens)
- Protected routes with dependency injection
- PostgreSQL integration via SQLAlchemy
- Database migrations with Alembic
- Automated testing with pytest
- Swagger/OpenAPI documentation
- Modular and scalable project structure

---

## 🛠️ Tech Stack

- FastAPI
- PostgreSQL
- SQLAlchemy
- Alembic
- Pydantic
- Pytest
- Uvicorn
- Python 3.12

---

## 🚀 Getting Started

### 1️⃣ Clone the repository

Clone from GitHub:

- git clone <your-repository-url>

### 2️⃣ Create virtual environment

Using PowerShell or VS Code terminal:

- python -m venv <name_of_venv>

Activate it:

- Windows: Scripts\activate
- Mac/Linux: source bin/activate

### 3️⃣ Install dependencies

- pip install -r requirements.txt

---

## ⚙️ Environment Variables

Create a `.env` file with your configuration:

- DATABASE_URL=your_postgres_connection_string
- SECRET_KEY=your_secret_key
- ALGORITHM=HS256
- ACCESS_TOKEN_EXPIRE_MINUTES=5

---

## ▶️ Run the Application

Start the FastAPI server:

- uvicorn main:app --reload

API will be available at:

- http://127.0.0.1:8000

Swagger documentation:

- http://127.0.0.1:8000/docs

---

## 🧪 Manual Tests (Authentication Verification)

This project includes a lightweight manual test suite for verifying JWT authentication behavior without requiring pytest.

### ▶️ Run Tests

python -m tests.test_auth_manual

### ✅ What Is Tested

- Valid access token authentication
- Expired token handling
- Invalid signature detection

### 📋 Example Output

Valid token test: testuser

Expired token test: None

Invalid signature test: None

All tests finished

---

## 🔑 JWT Authentication

- Authentication is handled using JWT tokens
- Tokens expire after 5 minutes (demo configuration)
- Expired tokens return 401 Unauthorized

---

## 🏗️ Project Structure

- db/ → Database configuration and session management
- models/ → SQLAlchemy database models
- schemas/ → Pydantic request/response schemas
- routes/user.py → User-related endpoints
- routes/simple.py → Simple/example routes
- security/ → JWT creation and authentication logic
- services/ → Business logic (e.g. current user retrieval)
- tests/ → Manual authentication verification scripts

---

## 🗄️ Database Migrations (Alembic)

Initialize Alembic:

- alembic init alembic

Create a migration:

- alembic revision --autogenerate -m "create column name"

Apply migrations:

- alembic upgrade head

---

## 🖥️ Frontend (Optional)

You can test the API using the Vue 3 client:

- https://github.com/persteenolsen/vue-fastapi-jwt-auth-client

This client supports JWT authentication and API interaction.

---

## ☁️ Deployment (Vercel)

To deploy on Vercel:

1. Configure vercel.json in your project
2. Create a new project in Vercel from your GitHub repository
3. Add environment variables from your .env file in Vercel
4. Push changes to GitHub
5. Vercel will automatically build and deploy your API

---

## 📝 Notes

- Make sure PostgreSQL is running and accessible
- Update models and run migrations when schema changes
- Use Swagger UI for quick manual testing
- Keep SECRET_KEY secure in production

---

Happy coding with FastAPI 🚀