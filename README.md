# FastAPI Authentication API

## Base URL

```
http://localhost:5000/mobile_api/auth
```

---

## Endpoints

### 1. Register
- **POST** `/register`
- **Request Body (JSON):**
  ```json
  {
    "username": "alice",
    "password": "mypassword",
    "user_type": "Service Provider",
    "role": "Admin"
  }
  ```
- **Response:**
  ```json
  { "msg": "User registered successfully" }
  ```

### 2. Login
- **POST** `/login`
- **Request Body (form-data):**
  - `username`: your username
  - `password`: your password
- **Response:**
  ```json
  {
    "access_token": "<JWT_TOKEN>",
    "token_type": "bearer"
  }
  ```

### 3. Logout
- **POST** `/logout`
- **Headers:**
  - `Authorization: Bearer <JWT_TOKEN>`
- **Response:**
  ```json
  { "msg": "Logout successful (client should delete token)" }
  ```

### 4. Get Current User
- **GET** `/current_user`
- **Headers:**
  - `Authorization: Bearer <JWT_TOKEN>`
- **Response:**
  ```json
  {
    "username": "alice",
    "user_type": "Service Provider",
    "role": "Admin",
    "is_active": true
  }
  ```

### 5. Get All Active Users
- **GET** `/active_users`
- **Headers:**
  - `Authorization: Bearer <JWT_TOKEN>`
- **Response:**
  ```json
  [
    {
      "username": "alice",
      "user_type": "Service Provider",
      "role": "Admin",
      "is_active": true
    },
  ]
  ```

### 6. Get All Users
- **GET** `/all_users`
- **Headers:**
  - `Authorization: Bearer <JWT_TOKEN>`
- **Response:**
  ```json
  [
    {
      "username": "alice",
      "user_type": "Service Provider",
      "role": "Admin",
      "is_active": true
    },
  ]
  ```

### 7. Protected Endpoint Example
- **GET** `/protected-endpoint`
- **Headers:**
  - `Authorization: Bearer <JWT_TOKEN>`
- **Response (if allowed):**
  ```json
  {
    "msg": "Hello, alice! You are a Admin in Service Provider."
  }
  ```

---

## Setup & Usage

1. **Clone the repository and navigate to the project directory.**
2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   venv\Scripts\activate  # On Windows
   # or
   source venv/bin/activate  # On Linux/Mac
   ```
3. **Install dependencies:**
   ```bash
   pip install -r auth_requirements.txt
   ```
4. **Create a `.env` file in the project root:**
   ```env
   MONGO_URI=mongodb://localhost:27017
   SECRET_KEY=your_secret_key_here
   ```
5. **Start the server:**
   ```bash
   uvicorn auth_api:app --host 0.0.0.0 --port 5000 --reload
   ```
6. **Test the endpoints** using Postman, curl, or any HTTP client.

---

## Notes
- All endpoints except `/register` and `/login` require a valid JWT token in the `Authorization` header.
- User roles and types are validated according to the defined structure in the code.
- The `is_active` field is only visible in the database and user info endpoints. 
