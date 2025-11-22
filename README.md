# Chat App

A real-time secure chat application with end-to-end encryption, built with React and Node.js.

## Features

- 🔐 End-to-end message encryption
- 👥 Real-time messaging with Socket.IO
- 🔑 User authentication with JWT
- 💬 Secure conversations between users
- 📱 Responsive Material-UI design

## Tech Stack

**Frontend:**
- React 19
- Vite
- Material-UI
- Socket.IO Client
- Crypto-JS

**Backend:**
- Node.js
- Express
- Socket.IO
- MongoDB / Mongoose
- JWT Authentication
- bcryptjs

## Getting Started

### Prerequisites
- Node.js
- MongoDB

### Installation

1. Clone the repository
2. Install backend dependencies:
   ```bash
   cd backend
   npm install
   ```

3. Install frontend dependencies:
   ```bash
   cd frontend
   npm install
   ```

4. Set up environment variables in `backend/.env`:
   ```
   MONGODB_URI=your_mongodb_connection_string
   JWT_SECRET=your_jwt_secret
   ```

### Running the Application

**Backend:**
```bash
cd backend
node server.js
```

**Frontend:**
```bash
cd frontend
npm run dev
```

The frontend will be available at `http://localhost:5173` and the backend at `http://localhost:3000`.

## Project Structure

```
chat-app/
├── backend/          # Express server with Socket.IO
│   └── server.js     # Main server file
└── frontend/         # React application
    └── src/          # Source files
```

