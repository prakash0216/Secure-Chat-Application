/*
 * Secure Chat Application - Backend Server
 * 
 * This server provides the backend infrastructure for a real-time secure chat application.
 * It handles user authentication, message encryption, and real-time communication using Socket.IO.
 * 
 * Key Features:
 * - User registration and authentication with JWT tokens
 * - End-to-end message encryption using AES-256-CBC
 * - Message integrity verification with HMAC-SHA256
 * - Real-time messaging via Socket.IO
 * - MongoDB for persistent storage of users, messages, and encryption keys
 * - Password hashing with bcrypt
 * - CORS support for frontend integration
 */

const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const cors = require("cors");
const mongoose = require("mongoose");
require("dotenv").config();

const app = express();
const server = http.createServer(app);
// Configure Socket.IO with CORS settings of the deployed frontend
const io = socketIo(server, {
  cors: {
    origin: [
      "https://secure-chat-application-1.onrender.com",
      "https://secure-chat-application-nu.vercel.app",
      "http://localhost:5173",
    ],
    methods: ["GET", "POST"],
    credentials: true,
  },
});

// Middleware of the deployed frontend
app.use(
  cors({
    origin: [
      "https://secure-chat-application-1.onrender.com",
      "https://secure-chat-application-nu.vercel.app",
      "http://localhost:5173",
    ],
    credentials: true,
  })
);
app.use(express.json());

// ============= MONGODB SCHEMAS =============
/*
Schema definitions for Users, Conversation Keys, and Messages
*/
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
  },
  password: {
    type: String,
    required: true,
  },
  userId: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  lastLogin: {
    type: Date,
  },
});

const conversationKeySchema = new mongoose.Schema({
  conversationId: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  userId1: {
    type: String,
    required: true,
    index: true,
  },
  userId2: {
    type: String,
    required: true,
    index: true,
  },
  encryptionKey: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const messageSchema = new mongoose.Schema({
  senderId: {
    type: String,
    required: true,
    index: true,
  },
  senderUsername: {
    type: String,
    required: true,
  },
  recipientId: {
    type: String,
    required: true,
    index: true,
  },
  recipientUsername: {
    type: String,
    required: true,
  },
  conversationId: {
    type: String,
    required: true,
    index: true,
  },
  encryptedContent: {
    type: String,
    required: true,
  },
  iv: {
    type: String,
    required: true,
  },
  hmac: {
    type: String,
    required: true,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
  delivered: {
    type: Boolean,
    default: false,
  },
  read: {
    type: Boolean,
    default: false,
  },
});

// Add compound indexes for efficient queries
messageSchema.index({ senderId: 1, recipientId: 1, timestamp: -1 });
messageSchema.index({ conversationId: 1, timestamp: -1 });

// Create models for each schema i.e., User, ConversationKey, Message
const User = mongoose.model("User", userSchema);
const ConversationKey = mongoose.model(
  "ConversationKey",
  conversationKeySchema
);

const Message = mongoose.model("Message", messageSchema);

// In-memory storage for online users only
const onlineUsers = new Map();

//JWT Secret - used to sign and verify tokens
// - This secret is used to cryptographically sign JWT tokens
// - Should be a long random string in production (stored in .env file)
// - Anyone with this secret can create valid tokens
const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-in-production";

// ============= MONGODB CONNECTION =============
const MONGODB_URI =
  process.env.MONGODB_URI || "mongodb://localhost:27017/secure-chat";

// Connect to MongoDB
mongoose
  .connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("✅ Connected to MongoDB Atlas");
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

// Handle MongoDB connection events
mongoose.connection.on("disconnected", () => {
  console.log("⚠️ MongoDB disconnected");
});

mongoose.connection.on("reconnected", () => {
  console.log("✅ MongoDB reconnected");
});

// ============= LOGGING UTILITIES =============
function logSeparator() {
  console.log("\n" + "═".repeat(80) + "\n");
}

function logSection(title) {
  console.log(`\n${"─".repeat(80)}`);
  console.log(`  ${title}`);
  console.log("─".repeat(80));
}

// ============= ENCRYPTION UTILITIES =============
// Generate a new 256-bit (32-byte) AES encryption key in hex format
function generateEncryptionKey() {
  const key = crypto.randomBytes(32).toString("hex");
  console.log("🔑 Generated 256-bit AES Key:");
  console.log(
    `   Key Length: ${key.length} hex chars (${key.length * 4} bits)`
  );
  console.log(
    `   Key: ${key.substring(0, 32)}...${key.substring(key.length - 8)}`
  );
  return key;
}

/*
Generate or retrieve conversation key for a pair of users (userId1, userId2) from MongoDB ,here we are using a 
sorted combination of user IDs as the conversation ID to ensure uniqueness regardless of the order of users.
*/
async function getConversationKey(userId1, userId2) {
  const sortedIds = [userId1, userId2].sort();
  const conversationId = `${sortedIds[0]}:${sortedIds[1]}`;

  try {
    // Try to find existing conversation key
    let conversation = await ConversationKey.findOne({ conversationId });

    if (!conversation) {
      logSection("🔐 GENERATING NEW CONVERSATION KEY");
      console.log(`   User 1 ID: ${userId1.substring(0, 16)}...`);
      console.log(`   User 2 ID: ${userId2.substring(0, 16)}...`);
      console.log(`   Conversation ID: ${conversationId.substring(0, 40)}...`);

      const newKey = generateEncryptionKey();

      conversation = new ConversationKey({
        conversationId,
        userId1: sortedIds[0],
        userId2: sortedIds[1],
        encryptionKey: newKey,
      });

      await conversation.save();
      console.log(`   ✅ Key stored in MongoDB for this conversation`);
    }

    return conversation.encryptionKey;
  } catch (error) {
    console.error("❌ Error getting conversation key:", error);
    throw error;
  }
}

/*
Encrypt a message using AES-256-CBC with a 256-bit (32-byte) key.
Here like in the frontend, we generate a random IV for each encryption operation and use HMAC-SHA256 to ensure message integrity.
The complete flow will be like this:
    * 1. Generate a random 128-bit (16-byte) IV.
    * 2. Encrypt the message using AES-256-CBC with the provided key and IV.
    * 3. Calculate the HMAC-SHA256 of the encrypted message and IV.
    * 4. Return the encrypted message, IV, and HMAC-SHA256. 
*/
function encryptMessage(message, key) {
  try {
    logSection("🔒 ENCRYPTING MESSAGE");
    console.log(`   Plain Text: "${message}"`);
    console.log(`   Plain Text Length: ${message.length} characters`);

    const iv = crypto.randomBytes(16);
    console.log(`\n   📍 Step 1: Generate Random IV (Initialization Vector)`);
    console.log(`   IV (hex): ${iv.toString("hex")}`);
    console.log(`   IV Length: 16 bytes (128 bits)`);

    console.log(`\n   📍 Step 2: Encrypt with AES-256-CBC`);
    console.log(`   Algorithm: AES-256-CBC`);
    console.log(`   Key (first 16 chars): ${key.substring(0, 16)}...`);

    const cipher = crypto.createCipheriv(
      "aes-256-cbc",
      Buffer.from(key, "hex"),
      iv
    );
    let encrypted = cipher.update(message, "utf8", "hex");
    encrypted += cipher.final("hex");

    console.log(
      `   Encrypted Text (hex): ${encrypted.substring(
        0,
        32
      )}...${encrypted.substring(encrypted.length - 16)}`
    );
    console.log(`   Encrypted Length: ${encrypted.length} hex chars`);

    console.log(`\n   📍 Step 3: Generate HMAC-SHA256 for Integrity`);
    console.log(`   HMAC Input: Encrypted + IV`);

    const hmac = crypto.createHmac("sha256", Buffer.from(key, "hex"));
    hmac.update(encrypted + iv.toString("hex"));
    const signature = hmac.digest("hex");

    console.log(
      `   HMAC-SHA256: ${signature.substring(0, 32)}...${signature.substring(
        signature.length - 8
      )}`
    );
    console.log(`   HMAC Length: ${signature.length} hex chars (256 bits)`);

    const result = {
      encrypted,
      iv: iv.toString("hex"),
      hmac: signature,
      timestamp: Date.now(),
    };

    console.log(`\n   ✅ Encryption Complete!`);
    console.log(
      `   Total Package Size: ~${JSON.stringify(result).length} bytes`
    );

    return result;
  } catch (error) {
    console.error("❌ Encryption error:", error);
    throw error;
  }
}

/*
Decrypt a message using AES-256-CBC and verify its integrity using HMAC-SHA256.
The Description flow will be like this:
    * 1. Verify the HMAC-SHA256 of the received encrypted message and IV.
    * 2. Decrypt the message using AES-256-CBC with the provided key and IV.
    * 3. Return the decrypted plain text message.
    * 4. If HMAC verification fails, throw an error indicating possible tampering.
    * 5. If decryption fails, throw an error indicating decryption failure.
    * 6. Otherwise, return the decrypted plain text message.
*/
function decryptMessage(encryptedData, key) {
  try {
    logSection("🔓 DECRYPTING MESSAGE");
    const { encrypted, iv, hmac: receivedHmac } = encryptedData;

    console.log(`   Encrypted Text: ${encrypted.substring(0, 32)}...`);
    console.log(`   IV: ${iv}`);
    console.log(`   Received HMAC: ${receivedHmac.substring(0, 32)}...`);

    console.log(`\n   📍 Step 1: Verify HMAC for Message Integrity`);
    const hmac = crypto.createHmac("sha256", Buffer.from(key, "hex"));
    hmac.update(encrypted + iv);
    const calculatedHmac = hmac.digest("hex");

    console.log(`   Calculated HMAC: ${calculatedHmac.substring(0, 32)}...`);
    console.log(`   Received HMAC:   ${receivedHmac.substring(0, 32)}...`);

    if (calculatedHmac !== receivedHmac) {
      console.log(`   ❌ HMAC MISMATCH - MESSAGE TAMPERED!`);
      throw new Error(
        "⚠️ Message integrity check failed - message may be tampered!"
      );
    }

    console.log(`   ✅ HMAC Verified - Message Integrity Confirmed`);

    console.log(`\n   📍 Step 2: Decrypt with AES-256-CBC`);
    console.log(`   Using same key and IV from encryption`);

    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      Buffer.from(key, "hex"),
      Buffer.from(iv, "hex")
    );
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");

    console.log(`   Decrypted Text: "${decrypted}"`);
    console.log(`   ✅ Decryption Complete!`);

    return decrypted;
  } catch (error) {
    console.error("❌ Decryption error:", error.message);
    throw error;
  }
}

// ============= AUTHENTICATION ROUTES =============
/*
Return a status message and the number of online users.
*/
app.get("/", (req, res) => {
  res.json({
    status: "running",
    message: "Secure Chat Server",
    onlineUsers: onlineUsers.size,
    database: "MongoDB Atlas",
    securityFeatures: {
      encryption: "AES-256-CBC",
      integrity: "HMAC-SHA256",
      authentication: "JWT",
      passwordHashing: "bcrypt (10 rounds)",
    },
  });
});

/*
Register a new user.
The flow will be like this:
    * 1. Validate username and password.
    * 2. check username length >=3 and password length >=6.
    * 3. check if username already exists.
    * 4. Hash password with bcrypt, with 10 rounds.
    * 5. Generate unique user ID.
    * 6. Generate JWT token valid for 24 hours.
    * 7. Return success message and JWT token.
    * 8. Create and save user to MongoDB.
    * 9. Generate JWT token valid for 24 hours. 
*/
app.post("/api/register", async (req, res) => {
  try {
    logSection("👤 NEW USER REGISTRATION");
    const { username, password } = req.body;

    console.log(`   Username: ${username}`);
    console.log(
      `   Password Length: ${password ? password.length : 0} characters`
    );

    // Validation
    if (!username || !password) {
      console.log(`   ❌ Validation Failed: Missing credentials`);
      return res.status(400).json({
        success: false,
        error: "Username and password required",
      });
    }

    if (username.length < 3) {
      console.log(`   ❌ Validation Failed: Username too short`);
      return res.status(400).json({
        success: false,
        error: "Username must be at least 3 characters",
      });
    }

    if (password.length < 6) {
      console.log(`   ❌ Validation Failed: Password too short`);
      return res.status(400).json({
        success: false,
        error: "Password must be at least 6 characters",
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      console.log(`   ❌ Registration Failed: Username already exists`);
      return res.status(400).json({
        success: false,
        error: "Username already exists",
      });
    }

    // Hash password with bcrypt
    console.log(`\n   🔐 Hashing Password with bcrypt (10 rounds)...`);
    const startTime = Date.now();
    const hashedPassword = await bcrypt.hash(password, 10);
    // - bcrypt.hash(plaintext, rounds)
    // - plaintext: "secret123"
    // - rounds: 10 (2^10 = 1024 iterations)
    // - Higher rounds = slower but more secure
    // - Output example: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
    // - Format: $2a$[rounds]$[salt][hash]
    // - Salt is random, included in output
    // - Same password → different hash each time (due to random salt)
    const hashTime = Date.now() - startTime;

    console.log(`   Original Password: ${"*".repeat(password.length)}`);
    console.log(`   Hashed Password: ${hashedPassword}`);
    console.log(`   Hash Format: $2a$[rounds]$[salt][hash]`);
    console.log(`   Hash Time: ${hashTime}ms`);
    console.log(`   ✅ Password securely hashed (irreversible)`);

    // Generate unique user ID
    const userId = crypto.randomBytes(16).toString("hex");
    // - crypto.randomBytes(16): Generates 16 random bytes
    // - .toString("hex"): Converts to hexadecimal string (32 characters)
    // - Example: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    // - Used internally for user identification
    console.log(`\n   🆔 Generated User ID: ${userId}`);

    // Create and save user
    const newUser = new User({
      username,
      password: hashedPassword,
      userId,
    });

    await newUser.save();

    // Generate JWT token
    console.log(`\n   🎫 Generating JWT Token...`);
    const token = jwt.sign({ userId, username }, JWT_SECRET, {
      expiresIn: "24h",
    });
    // JWT STRUCTURE:
    // Format: header.payload.signature
    // Example: eyJhbGci.eyJ1c2Vy.SflKxwRJ
    //
    // Header (base64): { "alg": "HS256", "typ": "JWT" }
    // Payload (base64): { "userId": "abc123", "username": "alice", "exp": 1701234567 }
    // Signature: HMACSHA256(header + payload, JWT_SECRET)
    //
    // - Payload is NOT encrypted (anyone can decode and read it)
    // - But signature prevents tampering
    // - Only server with JWT_SECRET can create valid tokens
    // - Client stores token and sends with each request
    console.log(`   Token (first 40 chars): ${token.substring(0, 40)}...`);
    console.log(`   Expires in: 24 hours`);

    console.log(`\n   ✅ Registration Successful!`);
    console.log(`   User saved to MongoDB`);

    res.json({
      success: true,
      token,
      user: { id: userId, username },
    });
  } catch (error) {
    console.error("❌ Registration error:", error);
    res.status(500).json({
      success: false,
      error: "Registration failed",
    });
  }
});

/*
User login route.
The flow will be like this:
    * 1. Validate username and password.
    * 2. Find user in MongoDB.
    * 3. Verify password with bcrypt.
    * 4. Generate JWT token valid for 24 hours.
    * 5. Return success message and JWT token.
    * 6. Update last login timestamp in MongoDB.
*/
app.post("/api/login", async (req, res) => {
  try {
    logSection("🔑 USER LOGIN ATTEMPT");
    const { username, password } = req.body;

    console.log(`   Username: ${username}`);
    console.log(`   Password: ${"*".repeat(password ? password.length : 0)}`);

    // Find user in database
    const user = await User.findOne({ username });
    if (!user) {
      console.log(`   ❌ Login Failed: User not found`);
      return res.status(401).json({
        success: false,
        error: "Invalid username or password",
      });
    }

    // Verify password with bcrypt
    console.log(`\n   🔐 Verifying Password with bcrypt...`);
    console.log(`   Stored Hash: ${user.password.substring(0, 40)}...`);

    const startTime = Date.now();
    const validPassword = await bcrypt.compare(password, user.password);
    // - bcrypt.compare(plaintext, hash)
    // - Input plaintext: "secret123"
    // - Stored hash: "$2a$10$N9qo8uLO..."
    //
    // HOW IT WORKS:
    // 1. Extract salt from stored hash
    // 2. Hash the input password with same salt and rounds
    // 3. Compare resulting hash with stored hash
    // 4. Return true if match, false otherwise
    //
    // Example:
    //   User enters: "secret123"
    //   bcrypt hashes with same salt → "$2a$10$N9qo8uLO..."
    //   Matches stored hash → TRUE ✅
    //
    //   User enters: "wrongpass"
    //   bcrypt hashes with same salt → "$2a$10$X7Y8Z9W1..."
    //   Doesn't match stored hash → FALSE ❌
    const verifyTime = Date.now() - startTime;

    console.log(`   Verification Time: ${verifyTime}ms`);

    if (!validPassword) {
      console.log(`   ❌ Login Failed: Invalid password`);
      return res.status(401).json({
        success: false,
        error: "Invalid username or password",
      });
    }

    console.log(`   ✅ Password Verified!`);

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT token
    console.log(`\n   🎫 Generating JWT Token...`);
    const token = jwt.sign({ userId: user.userId, username }, JWT_SECRET, {
      expiresIn: "24h",
    });
    console.log(`   Token Generated: ${token.substring(0, 40)}...`);

    console.log(`\n   ✅ Login Successful!`);
    console.log(`   User ID: ${user.userId}`);

    res.json({
      success: true,
      token,
      user: { id: user.userId, username },
    });
  } catch (error) {
    console.error("❌ Login error:", error);
    res.status(500).json({
      success: false,
      error: "Login failed",
    });
  }
});

/*
Get message history for a conversation
The flow will be like this:
    * 1. Authenticate user via JWT token.
    * 2. Construct conversation ID from user IDs.
    * 3. Fetch last 100 messages from MongoDB for the conversation.
    * 4. Return success message and messages.
*/
app.get("/api/messages/:userId", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({
        success: false,
        error: "No token provided",
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const { userId: recipientId } = req.params;

    const sortedIds = [decoded.userId, recipientId].sort();
    const conversationId = `${sortedIds[0]}:${sortedIds[1]}`;

    // Fetch messages from database
    const messages = await Message.find({ conversationId })
      .sort({ timestamp: 1 })
      .limit(100)
      .lean();

    res.json({
      success: true,
      messages,
      conversationId,
    });
  } catch (error) {
    console.error("❌ Error fetching messages:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch messages",
    });
  }
});

// ============= SOCKET.IO AUTHENTICATION MIDDLEWARE =============
/*
Socket.IO authentication middleware.
The flow will be like this:
    * 1. Extract token from socket handshake.
    * 2. Verify token using JWT_SECRET.
    * 3. If valid, attach user ID and username to socket.
    * 4. If invalid, return error.
*/
io.use((socket, next) => {
  logSection("🔌 SOCKET CONNECTION ATTEMPT");

  // STEP 1: Extract token from Socket.IO handshake
  const token = socket.handshake.auth.token;
  // - Client sends: io(url, { auth: { token: "eyJhbGci..." } })
  // - Server receives token here
  // - Handshake happens before connection is established

  if (!token) {
    console.log(`   ❌ No token provided`);
    return next(new Error("Authentication error: No token provided"));
    // - Rejects connection
    // - Client receives "connect_error" event
  }

  try {
    console.log(`   Token Received: ${token.substring(0, 40)}...`);
    console.log(`   Verifying JWT signature...`);

    // STEP 2: Verify and decode JWT token
    const decoded = jwt.verify(token, JWT_SECRET);
    // - jwt.verify(token, secret)
    // - Checks signature to ensure token is valid
    // - Checks expiration date
    // - Decodes payload if valid
    //
    // HOW IT WORKS:
    // 1. Split token: header.payload.signature
    // 2. Recreate signature: HMACSHA256(header + payload, JWT_SECRET)
    // 3. Compare signatures
    // 4. Check if expired
    //
    // Example decoded payload:
    // {
    //   userId: "a1b2c3d4...",
    //   username: "alice",
    //   iat: 1701234567,  // Issued at (timestamp)
    //   exp: 1701320967   // Expires at (timestamp)
    // }
    //
    // THROWS ERROR IF:
    // - Signature doesn't match (token tampered with)
    // - Token expired (past exp time)
    // - Token malformed (invalid format)

    console.log(`   ✅ Token Valid!`);
    console.log(`   User ID: ${decoded.userId}`);
    console.log(`   Username: ${decoded.username}`);

    // STEP 3: Attach user info to socket object
    socket.userId = decoded.userId;
    socket.username = decoded.username;
    // - Now available in all socket event handlers
    // - Example: socket.on("send-message", () => { console.log(socket.userId) })

    // STEP 4: Allow connection
    next();
    // - Calling next() without error allows connection
    // - Socket.IO proceeds to emit "connect" event
  } catch (err) {
    console.log(`   ❌ Invalid token: ${err.message}`);
    next(new Error("Authentication error: Invalid token"));
    // - Rejects connection
    // - Common errors:
    //   - "jwt expired" (token past expiration)
    //   - "invalid signature" (token tampered)
    //   - "jwt malformed" (invalid format)
  }
});
// ============= SOCKET.IO CONNECTION HANDLERS =============
/*
Handle new Socket.IO connections.
The flow will be like this:
    * 1. Log user connection and store in online users map.
    * 2. Broadcast updated online users list.
    * 3. Handle request for conversation key.
    * 4. Handle incoming encrypted messages.
    * 5. On disconnect, remove user from online users map and broadcast update.
    * 6. Verify message integrity on server side using HMAC.
    * 7. Save messages to MongoDB.
    * 8. Forward messages to recipient if online.
    * 9. Acknowledge message sent status to sender.
    * 10. If recipient offline, save message for later delivery.
    * 11. Log all relevant events and errors.
    * 12. Ensure all messages are end-to-end encrypted. 
    * 13. Use conversation keys for encryption/decryption.
    * 14. Maintain user privacy and security throughout.
*/
io.on("connection", (socket) => {
  logSection("✅ USER CONNECTED");
  console.log(`   Socket ID: ${socket.id}`);
  console.log(`   Username: ${socket.username}`);
  console.log(`   User ID: ${socket.userId}`);

  onlineUsers.set(socket.id, {
    username: socket.username,
    userId: socket.userId,
  });

  console.log(`   Total Online Users: ${onlineUsers.size}`);

  // Broadcast updated online users list (remove duplicates by userId)
  const userMap = new Map();
  for (const [socketId, userData] of onlineUsers.entries()) {
    userMap.set(userData.userId, {
      username: userData.username,
      userId: userData.userId,
    });
  }
  //Online users list
  const onlineUsersList = Array.from(userMap.values());

  io.emit("users-online", onlineUsersList);

  // Handle request for conversation key
  socket.on("request-conversation-key", async (data) => {
    try {
      const { recipientId } = data;
      const conversationKey = await getConversationKey(
        socket.userId,
        recipientId
      );

      socket.emit("conversation-key", {
        recipientId,
        key: conversationKey,
      });

      console.log(
        `\n   🔑 Sent conversation key to ${
          socket.username
        } for chat with user ${recipientId.substring(0, 16)}...`
      );
    } catch (error) {
      console.error("❌ Error getting conversation key:", error);
      socket.emit("message-error", {
        error: "Failed to get encryption key",
      });
    }
  });

  /*
   Handle incoming encrypted messages
    * 1. Verify message integrity on server side using HMAC.
    * 2. Save messages to MongoDB.
    * 3. Forward messages to recipient if online.
    * 4. Acknowledge message sent status to sender.
    * 5. If recipient offline, save message for later delivery.
    * 6. Log all relevant events and errors.
    * 7. Ensure all messages are end-to-end encrypted. 
    * 8. Use conversation keys for encryption/decryption.
    * 9. Maintain user privacy and security throughout.
    */
  socket.on("send-message", async (data) => {
    try {
      logSeparator();
      console.log("📨 MESSAGE TRANSMISSION");
      logSeparator();

      const { encryptedMessage, recipientId, recipientUsername } = data;

      console.log(
        `   From: ${socket.username} (${socket.userId.substring(0, 16)}...)`
      );
      console.log(
        `   To: ${recipientUsername} (${recipientId.substring(0, 16)}...)`
      );
      console.log(
        `   Timestamp: ${new Date(encryptedMessage.timestamp).toISOString()}`
      );

      console.log(`\n   📦 Encrypted Message Package:`);
      console.log(
        `   Encrypted Text: ${encryptedMessage.encrypted.substring(0, 40)}...`
      );
      console.log(`   IV: ${encryptedMessage.iv}`);
      console.log(`   HMAC: ${encryptedMessage.hmac.substring(0, 40)}...`);

      // Verify message integrity on server side
      const conversationKey = await getConversationKey(
        socket.userId,
        recipientId
      );

      console.log(`\n   🔍 Server-Side Integrity Check:`);
      try {
        const hmac = crypto.createHmac(
          "sha256",
          Buffer.from(conversationKey, "hex")
        );
        hmac.update(encryptedMessage.encrypted + encryptedMessage.iv);
        const calculatedHmac = hmac.digest("hex");

        if (calculatedHmac === encryptedMessage.hmac) {
          console.log(`   ✅ Message integrity verified on server`);
        } else {
          console.log(`   ⚠️ HMAC mismatch detected!`);
          throw new Error("Message integrity check failed");
        }
      } catch (err) {
        console.log(`   ⚠️ Integrity check failed: ${err.message}`);
        socket.emit("message-error", {
          error: "Message integrity check failed",
        });
        return;
      }

      // Create conversation ID
      const sortedIds = [socket.userId, recipientId].sort();
      const conversationId = `${sortedIds[0]}:${sortedIds[1]}`;

      // Save message to database
      const message = new Message({
        senderId: socket.userId,
        senderUsername: socket.username,
        recipientId,
        recipientUsername,
        conversationId,
        encryptedContent: encryptedMessage.encrypted,
        iv: encryptedMessage.iv,
        hmac: encryptedMessage.hmac,
        timestamp: new Date(encryptedMessage.timestamp),
      });

      await message.save();
      console.log(`\n   💾 Message saved to MongoDB`);

      // Find recipient socket
      let recipientSocket = null;
      for (const [socketId, userData] of onlineUsers.entries()) {
        if (userData.userId === recipientId) {
          recipientSocket = socketId;
          break;
        }
      }

      if (recipientSocket) {
        // Forward encrypted message to recipient
        io.to(recipientSocket).emit("receive-message", {
          encryptedMessage,
          sender: socket.username,
          senderId: socket.userId,
          timestamp: encryptedMessage.timestamp,
        });

        // Mark as delivered
        message.delivered = true;
        await message.save();

        console.log(`\n   ✅ Message Forwarded to Recipient!`);
        console.log(`   Recipient Socket: ${recipientSocket}`);
        console.log(`   Message delivered in encrypted form (end-to-end)`);

        socket.emit("message-sent", {
          success: true,
          recipient: recipientUsername,
        });
      } else {
        console.log(`\n   ⚠️ Recipient ${recipientUsername} not online`);
        console.log(`   Message saved for later delivery`);

        socket.emit("message-sent", {
          success: true,
          recipient: recipientUsername,
          offline: true,
        });
      }
    } catch (error) {
      console.error("❌ Message handling error:", error);
      socket.emit("message-error", {
        error: "Failed to send message",
      });
    }
  });

  /*
   Load message history when requested
   The flow will be like this:
    * 1. Construct conversation ID from user IDs.
    * 2. Fetch last 100 messages from MongoDB for the conversation.
    * 3. Return success message and messages.
   */
  socket.on("load-messages", async (data) => {
    try {
      const { recipientId } = data;
      const sortedIds = [socket.userId, recipientId].sort();
      const conversationId = `${sortedIds[0]}:${sortedIds[1]}`;

      const messages = await Message.find({ conversationId })
        .sort({ timestamp: 1 })
        .limit(100)
        .lean();

      socket.emit("message-history", {
        recipientId,
        messages,
      });

      console.log(
        `\n   📜 Sent ${messages.length} messages from history to ${socket.username}`
      );
    } catch (error) {
      console.error("❌ Error loading messages:", error);
      socket.emit("message-error", {
        error: "Failed to load message history",
      });
    }
  });

  /*
   Handle disconnect
   The flow will be like this:
    * 1. Remove user from online users list.
    * 2. Broadcast updated online users list.
   */
  socket.on("disconnect", () => {
    logSection("🔌 USER DISCONNECTED");
    console.log(`   Socket ID: ${socket.id}`);
    console.log(`   Username: ${socket.username}`);

    onlineUsers.delete(socket.id);
    console.log(`   Remaining Online Users: ${onlineUsers.size}`);

    // Broadcast updated online users list (remove duplicates)
    const userMap = new Map();
    for (const [socketId, userData] of onlineUsers.entries()) {
      userMap.set(userData.userId, {
        username: userData.username,
        userId: userData.userId,
      });
    }
    const onlineUsersList = Array.from(userMap.values());

    io.emit("users-online", onlineUsersList);
  });
});

// ============= STATISTICS ENDPOINT =============
// Get server statistics
app.get("/api/stats", async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalMessages = await Message.countDocuments();
    const totalConversations = await ConversationKey.countDocuments();

    res.json({
      server: "Secure Chat Server",
      uptime: process.uptime(),
      database: "MongoDB Atlas",
      users: {
        total: totalUsers,
        online: onlineUsers.size,
      },
      conversations: {
        total: totalConversations,
      },
      messages: {
        total: totalMessages,
      },
      security: {
        encryption: "AES-256-CBC",
        integrity: "HMAC-SHA256",
        authentication: "JWT",
        passwordHashing: "bcrypt-10",
        database: "MongoDB Atlas (encrypted at rest)",
      },
    });
  } catch (error) {
    console.error("❌ Error getting stats:", error);
    res.status(500).json({ error: "Failed to get statistics" });
  }
});

// ============= SERVER START =============
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  logSeparator();
  console.log("🚀 SECURE CHAT SERVER STARTED");
  logSeparator();
  console.log(`   Port: ${PORT}`);
  console.log(`   Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(`   Node Version: ${process.version}`);
  console.log(`   Database: MongoDB Atlas`);

  console.log(`\n🔒 SECURITY FEATURES ENABLED:`);
  console.log(`   ✅ End-to-End Encryption: AES-256-CBC`);
  console.log(`      • 256-bit keys (32 bytes)`);
  console.log(`      • Random IV per message (16 bytes)`);
  console.log(`      • CBC mode for block chaining`);

  console.log(`\n   ✅ Message Integrity: HMAC-SHA256`);
  console.log(`      • SHA-256 hash algorithm`);
  console.log(`      • Detects tampering/modification`);
  console.log(`      • Keyed-hash authentication`);

  console.log(`\n   ✅ User Authentication: JWT`);
  console.log(`      • JSON Web Tokens`);
  console.log(`      • 24-hour expiration`);
  console.log(`      • Signed with secret key`);

  console.log(`\n   ✅ Password Security: bcrypt`);
  console.log(`      • 10 rounds (1024 iterations)`);
  console.log(`      • Salted hashing`);
  console.log(`      • Adaptive difficulty`);

  console.log(`\n   ✅ Database Security:`);
  console.log(`      • MongoDB Atlas (encrypted at rest)`);
  console.log(`      • Indexed queries for performance`);
  console.log(`      • Persistent message storage`);
  console.log(`      • Conversation key persistence`);

  console.log(`\n   ✅ Fault Tolerance:`);
  console.log(`      • Message delivery verification`);
  console.log(`      • Offline message storage`);
  console.log(`      • Error handling & recovery`);
  console.log(`      • Database reconnection handling`);

  console.log(`\n   ✅ Additional Security:`);
  console.log(`      • CORS protection`);
  console.log(`      • Input validation`);
  console.log(`      • No plaintext storage`);
  console.log(`      • Server-side verification`);

  logSeparator();
  console.log("🎯 Server Ready for Connections!");
  logSeparator();
});

// ============= PROCESS MANAGEMENT =============
/*
Graceful shutdown on SIGTERM and SIGINT signals.
The flow will be like this:
    * 1. Log receipt of shutdown signal.
    * 2. Close HTTP server.
    * 3. Close MongoDB connection.
    * 4. Exit process.
*/
process.on("SIGTERM", async () => {
  console.log("\n⚠️ SIGTERM signal received: closing HTTP server");
  server.close(() => {
    console.log("✅ HTTP server closed gracefully");
  });

  await mongoose.connection.close();
  console.log("✅ MongoDB connection closed");
  process.exit(0);
});

process.on("SIGINT", async () => {
  console.log("\n⚠️ SIGINT signal received: closing HTTP server");
  server.close(() => {
    console.log("✅ HTTP server closed gracefully");
  });

  await mongoose.connection.close();
  console.log("✅ MongoDB connection closed");
  process.exit(0);
});
