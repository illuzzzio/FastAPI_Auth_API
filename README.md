# 🔐 FastAPI User Authentication API

This is a simple **FastAPI** based user authentication API using **OAuth2**, designed for learning and testing purposes. It demonstrates secure password hashing, token-based authentication, and environment variable management.

---

## 🚀 Features

- User authentication with **OAuth2 password flow**
- Password hashing using **PassLib (bcrypt)**
- Secure token generation with **python-jose**
- Environment variables management with **python-dotenv**
- Simple fake in-memory database for testing

---

## 🧰 Tech Stack & Libraries

- [FastAPI](https://fastapi.tiangolo.com/)
- [Uvicorn](https://www.uvicorn.org/) (ASGI server)
- [python-jose](https://github.com/mpdavis/python-jose) for JWT token handling
- [PassLib](https://passlib.readthedocs.io/en/stable/) for password hashing
- [python-dotenv](https://github.com/theskumar/python-dotenv) for environment variables
- [python-multipart](https://github.com/tiangolo/fastapi/issues/1246) for form data parsing

---

## ⚙️ Installation & Setup

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd <your-project-folder>

2. Create and activate a virtual environment

python3 -m venv venv
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

3. Install dependencies

pip install fastapi uvicorn python-jose passlib[bcrypt] python-multipart python-dotenv

4. Generate a secret key for JWT

You can generate a secret key using OpenSSL:

openssl rand -hex 32

Copy the output and save it to a .env file as:

SECRET_KEY=your_generated_secret_key

🚀 Running the API

Start the server using Uvicorn:

uvicorn main:app --reload

This will start the API at http://localhost:8000
📋 API Endpoints Overview

    /token — OAuth2 token endpoint to get access tokens (login)

    /users/me — Get current logged-in user info (protected route)

    Other endpoints for user creation, etc. (if implemented)

🧪 Testing

Use Swagger UI or ReDoc autogenerated docs to test the API interactively.
⚠️ Notes

    This project uses a fake in-memory database for demo/testing only — not for production.

    Replace the fake DB with a real database for production usage.

    Keep your SECRET_KEY private and secure.

🙌 Contributions

Feel free to fork and open issues or pull requests!
📞 Contact

For any questions or help, please open an issue or contact the maintainer.
