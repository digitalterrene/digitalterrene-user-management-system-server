---
### **User Authentication and Management API Documentation**

This API allows for user authentication (signup, signin) and management (fetch, update, delete) of user accounts.
---

### **1. POST `/signup` - Sign up a new user**

#### **Description:**

Creates a new user by validating and encrypting the provided email and password. If the email is already taken, it returns an error. A CSRF token is generated for protection, and an authentication token is created and returned in a cookie.

#### **Request Body:**

```json
{
  "email": "user@example.com", // Email address of the user (required)
  "password": "password123" // User password (required)
}
```

#### **Response:**

- **201 Created**: User created successfully.

```json
{
  "message": "User created successfully"
}
```

- **400 Bad Request**: Invalid email or password, or if email is already in use.

```json
{
  "error": "Email is taken!"
}
```

#### **Cookies Set:**

- `AuthToken`: Authentication token (valid for 1 hour).
- `CSRF-TOKEN`: CSRF token to prevent cross-site request forgery (valid for 1 hour).

---

### **2. POST `/signin` - Sign in an existing user**

#### **Description:**

Signs in a user by validating the provided email and password. If valid, an authentication token is generated and sent as a cookie along with a CSRF token for protection.

#### **Request Body:**

```json
{
  "email": "user@example.com", // Email address of the user (required)
  "password": "password123" // User password (required)
}
```

#### **Response:**

- **200 OK**: User successfully signed in.

```json
{
  "message": "User successfully signed in"
}
```

- **400 Bad Request**: Invalid email or password.

```json
{
  "error": "Wrong password"
}
```

- **404 Not Found**: Email does not exist.

```json
{
  "error": "Email does not exist"
}
```

#### **Cookies Set:**

- `AuthToken`: Authentication token (valid for 24 hours).
- `CSRF-TOKEN`: CSRF token to prevent cross-site request forgery (valid for 1 hour).

---

### **3. GET `/user` - Fetch single user details**

#### **Description:**

Fetches the details of a single user by their `userId`. The `userId` is taken from the request object.

#### **Response:**

- **200 OK**: User details retrieved successfully.

```json
{
  "email": "user@example.com",
  "password": "hashed_password"
}
```

- **400 Bad Request**: Missing user ID.

```json
{
  "error": "Requested user ID is missing"
}
```

- **404 Not Found**: User not found.

```json
{
  "error": "Failed to fetch data with id: <userId>"
}
```

---

### **4. PUT `/update` - Update user details**

#### **Description:**

Allows updating of user details (such as email and password). The provided password is validated and encrypted before being updated in the database. If no updates are provided, the existing user data remains unchanged.

#### **Request Body:**

```json
{
  "email": "newuser@example.com", // New email address (optional)
  "password": "P@ssword.1" // New password (optional)
}
```

#### **Response:**

- **200 OK**: User details updated successfully.

```json
{
  "message": "User updated successfully"
}
```

- **400 Bad Request**: Invalid email or password.

```json
{
  "error": "Invalid email format"
}
```

- **404 Not Found**: User not found.

```json
{
  "error": "Failed to fetch data with id: <userId>"
}
```

---

### **5. DELETE `/delete` - Delete a user**

#### **Description:**

Deletes a user from the database using their `userId`. CSRF token validation is required to ensure the request is legitimate.

#### **Response:**

- **200 OK**: User successfully deleted.

```json
{
  "message": "User successfully deleted"
}
```

- **404 Not Found**: User not found.

```json
{
  "error": "Failed to delete user with id: <userId>"
}
```

---

### **6. GET `/users` - Fetch all users**

#### **Description:**

Fetches a list of all users from the database.

#### **Response:**

- **200 OK**: Returns an array of user objects.

```json
[
  {
    "email": "user1@example.com",
    "password": "hashed_password"
  },
  {
    "email": "user2@example.com",
    "password": "hashed_password"
  }
]
```

- **404 Not Found**: No users found.

```json
{
  "error": "No users found"
}
```

---

### **Authentication Middleware (`authenticate`)**

All the routes except `/signup` and `/signin` are protected by the `authenticate` middleware. This middleware verifies that the `AuthToken` cookie is present and valid. If the token is missing or invalid, the request will be rejected with a 401 Unauthorized status.

---

### **CSRF Token Middleware (`validateCsrfToken`)**

The `validateCsrfToken` middleware ensures that the CSRF token included in the request matches the one stored in the cookies. This middleware is applied to the `DELETE /delete` route to prevent cross-site request forgery attacks.

---

### **Utility Functions**

- **`validateEmail(email)`**: Validates the email format.
- **`validatePassword(password)`**: Validates the password strength (length and complexity).
- **`encryptData(field, data)`**: Encrypts sensitive data like passwords before storing them.
- **`createToken(userId)`**: Generates a JWT token for authentication.
- **`generateCsrfToken()`**: Generates a random CSRF token for protecting against cross-site request forgery.

---

### **Error Handling**

All API endpoints catch errors and send a response with a 500 status code and a JSON body containing the error message. For example:

```json
{
  "error": "Error message"
}
```

---

This documentation should help you understand the structure and functionality of the user management and authentication APIs. If you need further assistance or clarification, feel free to ask!
