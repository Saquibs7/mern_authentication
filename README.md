# 🔐 MERN Authentication System

A complete **MERN Stack Authentication System** with **Email OTP Verification**, **JWT-based login**, and **secure password reset**.  
Built using **MongoDB**, **Express**, **React**, and **Node.js**.

---
### frontend link: https://mern-authentication-green.vercel.app/
## 🚀 Features

- ✅ Register users with **Email OTP verification**
- ✅ Login using **JWT + HttpOnly cookies**
- ✅ Forgot & Reset Password functionality
- ✅ Resend OTP and limited OTP attempts (3 max)
- ✅ Fully modular and production-ready folder structure
- ✅ Secure password hashing with **bcryptjs**
- ✅ Async error handling middleware
- ✅ Protected routes for authenticated users

---

## backend setup
cd server
npm install
npm run dev

## frontend setup
cd client
npm install
npm run dev

## 🔑 Authentication Flow

### ➕ Register

1. User registers using **name**, **email**, and **password**  
2. Backend sends a **6-digit OTP** to the user's email  
3. User enters the OTP on the verification screen  
4. If OTP is correct and valid, the account is **marked as verified**  
5. A **JWT token** is generated and stored in a secure cookie  

---

### 🔐 Login

1. User logs in using **email** and **password**  
2. On successful authentication, a **JWT** is issued  
3. The JWT is stored inside an **HttpOnly cookie** for security  
4. Authenticated routes become accessible only for verified users  

---

### 🔁 Forgot Password

1. User requests a **password reset** using their email  
2. Backend generates a **secure reset token** and sends a **password reset link** via email  
3. User clicks the link and resets their password  
4. Upon successful reset, the user is automatically **logged in** with a new JWT token  

