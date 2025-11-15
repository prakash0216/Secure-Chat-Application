import React, { useState, useEffect, useRef } from "react";
import io from "socket.io-client";
import CryptoJS from "crypto-js";
import {
  Box,
  Paper,
  TextField,
  Button,
  Typography,
  Avatar,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  AppBar,
  Toolbar,
  Chip,
  Divider,
  Card,
  CardContent,
  IconButton,
  Badge,
  Alert,
  CircularProgress,
  Drawer,
  useMediaQuery,
  useTheme,
  Grid,
} from "@mui/material";
import {
  Lock,
  Send,
  LockOpen,
  Person,
  Logout,
  FiberManualRecord,
  Security,
  VerifiedUser,
  Menu as MenuIcon,
  ArrowBack,
  History,
} from "@mui/icons-material";

// const API_URL = "http://localhost:3000";
const API_URL = "https://secure-chat-application.onrender.com";

// ============= TAMPERING TEST UTILITIES =============
// Expose this globally so users can test tampering in console
if (typeof window !== "undefined") {
  // Store the socket globally so we can intercept messages
  window._chatSocket = null;
  window._lastEncryptedMessage = null;

  window.testTampering = function (encryptedMessage) {
    console.log(
      "%c⚠️ TAMPERING TEST - Modifying encrypted message",
      "color: #ef4444; font-size: 14px; font-weight: bold;"
    );
    console.log(
      "Original encrypted:",
      encryptedMessage.encrypted.substring(0, 40) + "..."
    );

    // Tamper with the encrypted content (change one byte)
    const tampered =
      encryptedMessage.encrypted.substring(0, 10) +
      "FF" +
      encryptedMessage.encrypted.substring(12);
    console.log("Tampered encrypted:", tampered.substring(0, 40) + "...");
    console.log(
      "%c⚠️ This will cause HMAC verification to FAIL",
      "color: #ef4444; font-weight: bold;"
    );

    return {
      ...encryptedMessage,
      encrypted: tampered,
    };
  };

  // Function to send last message with tampering
  window.sendTamperedMessage = function () {
    if (!window._chatSocket) {
      console.error(
        "%c❌ No active chat socket!",
        "color: #ef4444; font-weight: bold;"
      );
      return;
    }

    if (!window._lastEncryptedMessage) {
      console.error(
        "%c❌ No message to tamper! Send a message first.",
        "color: #ef4444; font-weight: bold;"
      );
      return;
    }

    console.log(
      "%c🔨 TAMPERING AND SENDING MESSAGE...",
      "color: #f59e0b; font-size: 16px; font-weight: bold;"
    );
    console.log("─".repeat(80));

    // Create tampered version
    const tampered = window.testTampering(
      window._lastEncryptedMessage.encryptedMessage
    );

    // Send tampered message
    console.log(
      "%c📤 Sending tampered message to recipient...",
      "color: #f59e0b; font-weight: bold;"
    );
    window._chatSocket.emit("send-message", {
      encryptedMessage: tampered,
      recipientId: window._lastEncryptedMessage.recipientId,
      recipientUsername: window._lastEncryptedMessage.recipientUsername,
    });

    console.log(
      "%c✅ Tampered message sent!",
      "color: #10b981; font-weight: bold;"
    );
    console.log(
      "%c⚠️ Recipient will see decryption error due to HMAC mismatch",
      "color: #ef4444;"
    );
    console.log("─".repeat(80));
  };

  console.log(
    "%c🔒 Secure Chat Debug Tools Available",
    "color: #667eea; font-size: 14px; font-weight: bold;"
  );
  console.log("%c1. Send a message normally", "color: #888;");
  console.log(
    "%c2. Call window.sendTamperedMessage() to resend with tampering",
    "color: #888;"
  );
  console.log(
    "%c3. The recipient will see the tampering detection message",
    "color: #888;"
  );
}

// ============= ENCRYPTION UTILITIES =============
/*
  Encrypts the message and flow will be like this:
  1. Generate random IV.
  2. Encrypt the message using AES-256-CBC with the provided key and IV.
  3. Generate HMAC-SHA256 for integrity check.
  4. Return encrypted message, IV, HMAC, and timestamp.
*/
const encryptMessage = (message, key) => {
  try {
    // STEP 1: Generate Random IV (Initialization Vector)
    const iv = CryptoJS.lib.WordArray.random(16);
    // - CryptoJS: JavaScript library for cryptographic operations
    // - lib.WordArray: CryptoJS's internal format for byte arrays
    // - .random(16): Generates 16 random bytes (128 bits)
    // - IV ensures same message encrypted twice produces different ciphertext
    // - 16 bytes is standard for AES (128-bit IV)

    // STEP 2: Encrypt the message using AES-256-CBC
    const encrypted = CryptoJS.AES.encrypt(
      message, // Plaintext message (string)
      CryptoJS.enc.Hex.parse(key), // Convert hex string key to CryptoJS format
      {
        iv: iv, // Use the random IV we generated
        mode: CryptoJS.mode.CBC, // CBC = Cipher Block Chaining mode
        padding: CryptoJS.pad.Pkcs7, // PKCS7 padding for incomplete blocks
      }
    );
    // - AES.encrypt(): Advanced Encryption Standard algorithm
    // - Key is 256-bit (64 hex characters = 32 bytes)
    // - CBC mode: Each block depends on previous block (more secure)
    // - PKCS7: Adds padding if message doesn't fit exact block size (16 bytes)

    // STEP 3: Convert encrypted result to hex string
    const encryptedHex = encrypted.ciphertext.toString(CryptoJS.enc.Hex);
    // - encrypted.ciphertext: Contains the actual encrypted bytes
    // - .toString(CryptoJS.enc.Hex): Converts to hexadecimal string for transmission
    // - Hex is easier to transmit over network than raw bytes

    // STEP 4: Convert IV to hex string
    const ivHex = iv.toString(CryptoJS.enc.Hex);
    // - IV also needs to be sent with message (not secret)
    // - Receiver needs IV to decrypt
    // - Converting to hex for network transmission

    // STEP 5: Generate HMAC-SHA256 signature for integrity
    const hmac = CryptoJS.HmacSHA256(
      encryptedHex + ivHex, // Combine encrypted message and IV
      CryptoJS.enc.Hex.parse(key) // Use same encryption key for HMAC
    );
    // - HMAC: Hash-based Message Authentication Code
    // - SHA256: 256-bit hash algorithm
    // - Purpose: Detects if message was tampered with during transmission
    // - Input: encrypted message + IV (concatenated)
    // - Key: Same 256-bit key used for encryption
    // - Output: 256-bit signature

    // STEP 6: Package everything for transmission
    const result = {
      encrypted: encryptedHex, // The encrypted message (hex string)
      iv: ivHex, // The IV used (hex string, 32 chars)
      hmac: hmac.toString(CryptoJS.enc.Hex), // Integrity signature (hex, 64 chars)
      timestamp: Date.now(), // When message was created (milliseconds)
    };
    // This object will be sent to the server via Socket.IO

    return result;
  } catch (error) {
    throw new Error("Encryption failed: " + error.message);
  }
};

/*
  Decrypts the message and flow will be like this:
  1. Verify HMAC for integrity.
  2. Decrypt the message using AES-256-CBC with the provided key and IV.
  3. Return the decrypted plain text message
*/
const decryptMessage = (encryptedData, key) => {
  try {
    // STEP 1: Extract components from received encrypted data
    const { encrypted, iv, hmac: receivedHmac } = encryptedData;
    // - encrypted: The ciphertext (hex string)
    // - iv: The IV used during encryption (hex string)
    // - receivedHmac: The HMAC signature from sender (hex string)

    // STEP 2: Calculate HMAC on received data
    const calculatedHmac = CryptoJS.HmacSHA256(
      encrypted + iv, // Same input as encryption
      CryptoJS.enc.Hex.parse(key) // Same key
    );
    // - We recalculate the HMAC using the received data
    // - If data was tampered with, HMAC will be different
    // - This is CRUCIAL for security - verifies integrity

    // STEP 3: Convert calculated HMAC to hex for comparison
    const calculatedHmacHex = calculatedHmac.toString(CryptoJS.enc.Hex);

    // STEP 4: Compare HMACs (integrity check)
    const passed = calculatedHmacHex === receivedHmac;
    // - String comparison of two 256-bit hashes
    // - If even ONE bit is different = tampering detected
    // - This is why HMAC is so important!

    // STEP 5: Log verification result to console
    console.log(
      "%c🔍 HMAC Integrity Check",
      `color: ${passed ? "#10b981" : "#ef4444"}; font-weight: bold;`
    );
    console.log("Received HMAC: ", receivedHmac.substring(0, 40) + "...");
    console.log("Calculated HMAC:", calculatedHmacHex.substring(0, 40) + "...");
    console.log(
      "Result:",
      passed
        ? "✅ VALID - Message is authentic"
        : "❌ FAILED - Message was tampered!"
    );

    // STEP 6: If HMAC doesn't match, REJECT the message
    if (!passed) {
      console.error(
        "%c❌ TAMPERING DETECTED!",
        "color: #ef4444; font-size: 16px; font-weight: bold;"
      );
      console.error(
        "The message HMAC does not match. This message has been modified in transit."
      );
      throw new Error(
        "⚠️ Message integrity check failed - tampering detected!"
      );
    }
    // - Security: NEVER decrypt if HMAC fails
    // - Prevents processing of tampered messages
    // - Error will show in UI as failed message

    // STEP 7: HMAC passed - safe to decrypt
    const decrypted = CryptoJS.AES.decrypt(
      { ciphertext: CryptoJS.enc.Hex.parse(encrypted) }, // Convert hex to bytes
      CryptoJS.enc.Hex.parse(key), // Convert key hex to bytes
      {
        iv: CryptoJS.enc.Hex.parse(iv), // Convert IV hex to bytes
        mode: CryptoJS.mode.CBC, // Must match encryption mode
        padding: CryptoJS.pad.Pkcs7, // Must match encryption padding
      }
    );
    // - AES.decrypt(): Reverses the encryption
    // - Must use EXACT same parameters as encryption:
    //   ✓ Same key
    //   ✓ Same IV (received with message)
    //   ✓ Same mode (CBC)
    //   ✓ Same padding (PKCS7)
    // - Output: CryptoJS WordArray with decrypted bytes

    // STEP 8: Convert decrypted bytes back to UTF-8 text
    const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
    // - .toString(CryptoJS.enc.Utf8): Converts bytes to readable string
    // - UTF-8: Standard text encoding (supports emojis, international characters)
    // - Result: Original plaintext message

    return decryptedText; // Return "Hello Bob"
  } catch (error) {
    throw new Error("Decryption failed: " + error.message);
  }
};

// ============= MAIN APP COMPONENT =============
function App() {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const [currentView, setCurrentView] = useState("login");
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [socket, setSocket] = useState(null);
  const [conversationKeys, setConversationKeys] = useState({});
  const [mobileDrawerOpen, setMobileDrawerOpen] = useState(false);
  const [showChatOnMobile, setShowChatOnMobile] = useState(false);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const [onlineUsers, setOnlineUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [messages, setMessages] = useState([]);
  const [messageInput, setMessageInput] = useState("");
  const [successMsg, setSuccessMsg] = useState("");
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [loadedConversations, setLoadedConversations] = useState(new Set());

  const messagesEndRef = useRef(null);

  /*
    Auto-login if token and user data are found in localStorage
  */
  useEffect(() => {
    const savedToken = localStorage.getItem("chatToken");
    const savedUser = localStorage.getItem("chatUser");

    if (savedToken && savedUser) {
      try {
        const userData = JSON.parse(savedUser);
        setToken(savedToken);
        setUser(userData);
        setCurrentView("chat");
        connectSocket(savedToken, userData);
      } catch (err) {
        localStorage.removeItem("chatToken");
        localStorage.removeItem("chatUser");
      }
    }
  }, []);

  // Auto-scroll to bottom on new messages
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Request conversation key when a user is selected
  // This is to ensure that the conversation key is available before loading message history
  useEffect(() => {
    if (socket && selectedUser && !conversationKeys[selectedUser.userId]) {
      console.log(
        `🔑 Requesting conversation key for ${selectedUser.username}`
      );
      socket.emit("request-conversation-key", {
        recipientId: selectedUser.userId,
      });
    }
  }, [selectedUser, socket, conversationKeys]);

  // Load message history only once per conversation
  // This is to ensure that the message history is only loaded once per conversation
  useEffect(() => {
    if (socket && selectedUser && conversationKeys[selectedUser.userId]) {
      if (!loadedConversations.has(selectedUser.userId)) {
        // Clear messages for this conversation first
        setMessages([]);
        loadMessageHistory();
        setLoadedConversations((prev) =>
          new Set(prev).add(selectedUser.userId)
        );
      }
    }
  }, [selectedUser, conversationKeys]);

  // ============= LOAD MESSAGE HISTORY =============
  // Load message history for selected user
  const loadMessageHistory = async () => {
    if (!selectedUser || !conversationKeys[selectedUser.userId]) return;

    setLoadingHistory(true);
    socket.emit("load-messages", { recipientId: selectedUser.userId });
  };

  // ============= AUTHENTICATION =============
  /*
    Handles user registration
    The flow will be like this:
    * 1. Send a POST request to the server to register the user.
    * 2. If the registration is successful, store the token and user data in localStorage.
    * 3. If the registration fails, display an error message.
    * 4. Update loading state accordingly.
    * 5. Connect to the socket server upon successful registration.
  */
  const handleRegister = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const response = await fetch(`${API_URL}/api/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (data.success) {
        setToken(data.token);
        setUser(data.user);
        localStorage.setItem("chatToken", data.token);
        localStorage.setItem("chatUser", JSON.stringify(data.user));
        setSuccessMsg("Registration successful! Connecting...");
        connectSocket(data.token, data.user);
      } else {
        setError(data.error);
      }
    } catch (err) {
      setError("Registration failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  /*
    Handles user login
    The flow will be like this:
    * 1. Send a POST request to the server to log in the user.
    * 2. If the login is successful, store the token and user data in localStorage.
    * 3. If the login fails, display an error message.
    * 4. Update loading state accordingly.
    * 5. Connect to the socket server upon successful login.
  */
  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const response = await fetch(`${API_URL}/api/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (data.success) {
        setToken(data.token);
        setUser(data.user);
        localStorage.setItem("chatToken", data.token);
        localStorage.setItem("chatUser", JSON.stringify(data.user));
        setSuccessMsg("Login successful! Connecting...");
        connectSocket(data.token, data.user);
      } else {
        setError(data.error);
      }
    } catch (err) {
      setError("Login failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  // ============= SOCKET CONNECTION =============
  /*
    Connects to the socket server with authentication
    The flow will be like this:
    * 1. Create a new socket connection to the server.
    * 2. Emit a "connect" event to the server.
    * 3. If the connection is successful, update the current view to "chat".
    * 4. Listen for various events such as "conversation-key", "users-online", "message-history", "receive-message", "message-sent", "message-error", and "disconnect".
    * 5. Update the relevant state variables based on the events received.
    * 6. Handle errors and disconnections appropriately.
    * 7. Store the socket instance in state.
    * 8. Log relevant information to the console for debugging.
    * 9. Request conversation keys as needed.
    * 10. Decrypt messages upon receipt using the appropriate conversation key.
    * 11. Manage offline message notifications.
    * 12. Ensure message history is decrypted and displayed correctly.
    * 13. Handle pending messages awaiting decryption keys.
    * 14. Maintain overall application state consistency.
    * 15. Provide user feedback through success and error messages.
    * 16. Ensure secure handling of encryption keys and messages.
  */
  const connectSocket = (authToken, userData) => {
    const newSocket = io(API_URL, {
      auth: { token: authToken },
      forceNew: true,
    });

    newSocket.on("connect", () => {
      console.log("✅ Connected to server");
      setCurrentView("chat");
      setSuccessMsg("");
    });

    newSocket.on("conversation-key", (data) => {
      console.log(`🔑 Received conversation key for user ${data.recipientId}`);
      setConversationKeys((prev) => ({
        ...prev,
        [data.recipientId]: data.key,
      }));
    });

    newSocket.on("users-online", (users) => {
      // Remove duplicates and filter out current user
      const uniqueUsers = users.filter(
        (u, index, self) =>
          u.userId !== userData.id &&
          index === self.findIndex((user) => user.userId === u.userId)
      );
      setOnlineUsers(uniqueUsers);
    });

    newSocket.on("message-history", (data) => {
      const { recipientId, messages: historyMessages } = data;

      console.log(
        `📥 Received ${
          historyMessages.length
        } messages from server for user ${recipientId.substring(0, 8)}...`
      );

      // Use a slight delay to ensure conversation key state has updated
      setTimeout(() => {
        setConversationKeys((currentKeys) => {
          const key = currentKeys[recipientId];

          if (!key) {
            console.log("⚠️ No key available yet for decrypting history");
            setLoadingHistory(false);
            return currentKeys;
          }

          try {
            const decryptedMessages = historyMessages.map((msg, index) => {
              try {
                const decrypted = decryptMessage(
                  {
                    encrypted: msg.encryptedContent,
                    iv: msg.iv,
                    hmac: msg.hmac,
                  },
                  key
                );

                return {
                  id: msg._id || `${msg.timestamp}-${index}`,
                  text: decrypted,
                  sender: msg.senderUsername,
                  senderId: msg.senderId,
                  timestamp: new Date(msg.timestamp).getTime(),
                  isOwn: msg.senderId === userData.id,
                  encrypted: true,
                };
              } catch (err) {
                console.error("❌ Failed to decrypt history message:", err);
                return {
                  id: msg._id || `${msg.timestamp}-${index}-error`,
                  text: "⚠️ Failed to decrypt message",
                  sender: msg.senderUsername,
                  senderId: msg.senderId,
                  timestamp: new Date(msg.timestamp).getTime(),
                  isOwn: msg.senderId === userData.id,
                  error: true,
                };
              }
            });

            console.log(`✅ Decrypted ${decryptedMessages.length} messages`);
            console.log(
              "📊 Message details:",
              decryptedMessages.map((m) => ({
                text: m.text.substring(0, 20),
                senderId: m.senderId.substring(0, 8),
                isOwn: m.isOwn,
              }))
            );

            setMessages(decryptedMessages);
            console.log(`📜 Set ${decryptedMessages.length} messages in state`);
          } catch (err) {
            console.error("❌ Error processing message history:", err);
          } finally {
            setLoadingHistory(false);
          }

          return currentKeys;
        });
      }, 50); // Small delay to let state update
    });

    newSocket.on("receive-message", (data) => {
      try {
        const key = conversationKeys[data.senderId];

        if (!key) {
          console.error(
            "❌ No conversation key found for sender:",
            data.senderId
          );
          newSocket.emit("request-conversation-key", {
            recipientId: data.senderId,
          });

          setMessages((prev) => [
            ...prev,
            {
              id: `pending-${Date.now()}-${data.senderId}`,
              text: "⚠️ Waiting for encryption key...",
              sender: data.sender,
              senderId: data.senderId,
              timestamp: data.timestamp,
              isOwn: false,
              error: true,
              pendingData: data,
            },
          ]);
          return;
        }

        const decrypted = decryptMessage(data.encryptedMessage, key);
        setMessages((prev) => [
          ...prev,
          {
            id: `msg-${data.timestamp}-${data.senderId}`,
            text: decrypted,
            sender: data.sender,
            senderId: data.senderId,
            timestamp: data.timestamp,
            isOwn: false,
            encrypted: true,
          },
        ]);
      } catch (err) {
        console.error("❌ Decryption failed:", err);
        setMessages((prev) => [
          ...prev,
          {
            id: `error-${Date.now()}-${data.senderId}`,
            text: "⚠️ Failed to decrypt message - " + err.message,
            sender: data.sender,
            senderId: data.senderId,
            timestamp: data.timestamp,
            isOwn: false,
            error: true,
          },
        ]);
      }
    });

    newSocket.on("message-sent", (data) => {
      console.log("✅ Message delivered");
      if (data.offline) {
        // Show notification that user is offline
        setError(
          `${data.recipient} is offline. Message saved for later delivery.`
        );
        setTimeout(() => setError(""), 3000);
      }
    });

    newSocket.on("message-error", (data) => {
      setError(data.error);
      setTimeout(() => setError(""), 3000);
    });

    newSocket.on("disconnect", () => {
      console.log("🔌 Disconnected from server");
    });

    newSocket.on("connect_error", (err) => {
      console.error("Connection error:", err.message);
      setError("Connection failed: " + err.message);
    });

    setSocket(newSocket);
    if (typeof window !== "undefined") {
      window._chatSocket = newSocket;
    }
  };

  useEffect(() => {
    if (!selectedUser) return;

    const key = conversationKeys[selectedUser.userId];
    if (!key) return;

    setMessages((prev) =>
      prev.map((msg) => {
        if (msg.pendingData && msg.senderId === selectedUser.userId) {
          try {
            const decrypted = decryptMessage(
              msg.pendingData.encryptedMessage,
              key
            );
            return {
              ...msg,
              text: decrypted,
              error: false,
              encrypted: true,
              pendingData: undefined,
            };
          } catch (err) {
            return msg;
          }
        }
        return msg;
      })
    );
  }, [conversationKeys, selectedUser]);

  // ============= SEND MESSAGE =============
  /*
    Handles sending a message
    The flow will be like this:
    * 1. Prevent default form submission behavior.
    * 2. Check if the message input is empty or no user is selected; if so, return early.
    * 3. Retrieve the conversation key for the selected user; if not available, show an error and return.
    * 4. Encrypt the message using the conversation key.
    * 5. Emit the "send-message" event to the server with the encrypted message and recipient details.
    * 6. Update the local messages state to include the newly sent message.
    * 7. Clear the message input field.
    * 8. Handle any encryption errors by displaying an error message.
    * 9. Provide user feedback through error messages as needed.
    * 10. Ensure secure handling of the message during encryption and transmission.
  */
  const handleSendMessage = (e) => {
    e.preventDefault();

    if (!messageInput.trim() || !selectedUser) return;

    const key = conversationKeys[selectedUser.userId];
    if (!key) {
      setError("Encryption key not available. Please wait...");
      setTimeout(() => setError(""), 3000);
      return;
    }

    try {
      const encrypted = encryptMessage(messageInput, key);

      if (typeof window !== "undefined") {
        window._lastEncryptedMessage = {
          encryptedMessage: encrypted,
          recipientId: selectedUser.userId,
          recipientUsername: selectedUser.username,
        };

        console.log(
          "%c📨 Message Encrypted and Ready",
          "color: #10b981; font-size: 14px; font-weight: bold;"
        );
        console.log("─".repeat(80));
        console.log("Message:", messageInput);
        console.log("Encrypted:", encrypted.encrypted.substring(0, 40) + "...");
        console.log("IV:", encrypted.iv);
        console.log("HMAC:", encrypted.hmac.substring(0, 40) + "...");
        console.log("─".repeat(80));
        console.log(
          "%cTo test tampering, call: window.sendTamperedMessage()",
          "color: #f59e0b; font-weight: bold;"
        );
      }

      socket.emit("send-message", {
        encryptedMessage: encrypted,
        recipientId: selectedUser.userId,
        recipientUsername: selectedUser.username,
      });

      setMessages((prev) => [
        ...prev,
        {
          id: `sent-${Date.now()}-${user.id}`,
          text: messageInput,
          sender: user.username,
          senderId: user.id,
          timestamp: Date.now(),
          isOwn: true,
          encrypted: true,
        },
      ]);

      setMessageInput("");
    } catch (err) {
      setError("Failed to encrypt message");
      setTimeout(() => setError(""), 3000);
    }
  };

  // ============= LOGOUT =============
  /*
    Handles user logout
    The flow will be like this:
    * 1. Disconnect from the socket server if connected.
    * 2. Clear all relevant state variables including user, token, socket, conversation keys, messages, and UI states.
    * 3. Remove user data and token from localStorage.
    * 4. Reset the application view to the login screen.
    * 5. Ensure a clean state for future logins.
    * 6. Provide user feedback through UI updates.
  */
  const handleLogout = () => {
    if (socket) {
      socket.disconnect();
    }
    setSocket(null);
    setUser(null);
    setToken(null);
    setConversationKeys({});
    setCurrentView("login");
    setMessages([]);
    setSelectedUser(null);
    setUsername("");
    setPassword("");
    setShowChatOnMobile(false);
    setLoadedConversations(new Set());
    localStorage.removeItem("chatToken");
    localStorage.removeItem("chatUser");
  };

  // ============= USER SELECTION =============
  // Handles user selection from the online users list
  const handleUserSelect = (u) => {
    setSelectedUser(u);
    // Only clear messages if switching to different user
    if (!selectedUser || selectedUser.userId !== u.userId) {
      setLoadingHistory(true);
    }
    if (isMobile) {
      setShowChatOnMobile(true);
      setMobileDrawerOpen(false);
    }
  };

  // Handles going back to users list on mobile
  const handleBackToUsers = () => {
    setShowChatOnMobile(false);
    setSelectedUser(null);
    setMessages([]);
  };

  // ============= SIDEBAR COMPONENT =============
  const SidebarContent = () => (
    <Box
      sx={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        bgcolor: "white",
      }}
    >
      <Paper elevation={0} sx={{ p: 2, bgcolor: "#f9f9f9" }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
          <Avatar sx={{ bgcolor: "#667eea", width: 48, height: 48 }}>
            {user?.username.charAt(0).toUpperCase()}
          </Avatar>
          <Box sx={{ flexGrow: 1 }}>
            <Typography variant="subtitle1" fontWeight="bold">
              {user?.username}
            </Typography>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
              <FiberManualRecord sx={{ fontSize: 12, color: "#10b981" }} />
              <Typography variant="caption" color="text.secondary">
                Online
              </Typography>
            </Box>
          </Box>
        </Box>
      </Paper>

      <Divider />

      <Box sx={{ flexGrow: 1, overflow: "auto", p: 1 }}>
        <Typography
          variant="overline"
          sx={{ px: 1, color: "text.secondary", fontWeight: "bold" }}
        >
          Online Users ({onlineUsers.length})
        </Typography>

        <List>
          {onlineUsers.map((u) => (
            <ListItem
              key={u.userId}
              component="div"
              onClick={() => handleUserSelect(u)}
              selected={selectedUser?.userId === u.userId}
              sx={{
                borderRadius: 1,
                mb: 0.5,
                cursor: "pointer",
                "&.Mui-selected": {
                  bgcolor: "#e3f2fd",
                  "&:hover": { bgcolor: "#bbdefb" },
                },
                "&:hover": {
                  bgcolor: "#f5f5f5",
                },
              }}
            >
              <ListItemAvatar>
                <Badge
                  overlap="circular"
                  anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
                  badgeContent={
                    <FiberManualRecord
                      sx={{ fontSize: 12, color: "#10b981" }}
                    />
                  }
                >
                  <Avatar sx={{ bgcolor: "#764ba2" }}>
                    {u.username.charAt(0).toUpperCase()}
                  </Avatar>
                </Badge>
              </ListItemAvatar>
              <ListItemText
                primary={u.username}
                secondary="Online"
                primaryTypographyProps={{ fontWeight: "medium" }}
              />
            </ListItem>
          ))}
        </List>

        {onlineUsers.length === 0 && (
          <Box sx={{ textAlign: "center", py: 4 }}>
            <Person sx={{ fontSize: 48, color: "#ccc" }} />
            <Typography variant="body2" color="text.secondary">
              No other users online
            </Typography>
          </Box>
        )}
      </Box>
    </Box>
  );

  // ============= RENDER AUTH VIEW =============
  if (currentView === "login" || currentView === "register") {
    return (
      <Box
        sx={{
          minHeight: "100vh",
          background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          p: { xs: 2, sm: 3 },
        }}
      >
        <Paper
          elevation={10}
          sx={{
            p: { xs: 3, sm: 4 },
            maxWidth: 400,
            width: "100%",
          }}
        >
          <Box sx={{ textAlign: "center", mb: 3 }}>
            <Lock
              sx={{ fontSize: { xs: 40, sm: 48 }, color: "#667eea", mb: 1 }}
            />
            <Typography
              variant="h4"
              fontWeight="bold"
              gutterBottom
              sx={{ fontSize: { xs: "1.75rem", sm: "2.125rem" } }}
            >
              Secure Chat
            </Typography>
            <Typography variant="body2" color="text.secondary">
              End-to-End Encrypted Messaging
            </Typography>
          </Box>

          <Box
            component="form"
            onSubmit={currentView === "login" ? handleLogin : handleRegister}
          >
            <TextField
              fullWidth
              label="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              margin="normal"
              required
              autoFocus
            />
            <TextField
              fullWidth
              label="Password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              margin="normal"
              required
            />

            {error && (
              <Alert severity="error" sx={{ mt: 2 }}>
                {error}
              </Alert>
            )}

            {successMsg && (
              <Alert severity="success" sx={{ mt: 2 }}>
                {successMsg}
              </Alert>
            )}

            <Button
              fullWidth
              variant="contained"
              size="large"
              type="submit"
              disabled={loading}
              sx={{
                mt: 3,
                background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
                "&:hover": {
                  background:
                    "linear-gradient(135deg, #5568d3 0%, #6a3f8f 100%)",
                },
              }}
            >
              {loading ? (
                <CircularProgress size={24} color="inherit" />
              ) : currentView === "login" ? (
                "Login"
              ) : (
                "Register"
              )}
            </Button>
          </Box>

          <Box sx={{ mt: 2, textAlign: "center" }}>
            <Typography variant="body2" color="text.secondary">
              {currentView === "login"
                ? "Don't have an account? "
                : "Already have an account? "}
              <Typography
                component="span"
                color="primary"
                sx={{ cursor: "pointer", fontWeight: "bold" }}
                onClick={() => {
                  setCurrentView(
                    currentView === "login" ? "register" : "login"
                  );
                  setError("");
                }}
              >
                {currentView === "login" ? "Register" : "Login"}
              </Typography>
            </Typography>
          </Box>

          <Divider sx={{ my: 3 }} />

          <Box
            sx={{
              display: "flex",
              gap: 1,
              justifyContent: "center",
              flexWrap: "wrap",
            }}
          >
            <Chip icon={<Lock />} label="AES-256" size="small" />
            <Chip icon={<VerifiedUser />} label="HMAC-SHA256" size="small" />
            <Chip icon={<Security />} label="JWT Auth" size="small" />
          </Box>
        </Paper>
      </Box>
    );
  }

  // ============= RENDER CHAT VIEW =============
  const currentConversationKey = selectedUser
    ? conversationKeys[selectedUser.userId]
    : null;

  return (
    <Box sx={{ display: "flex", height: "100vh", bgcolor: "#f5f5f5" }}>
      {/* Desktop Sidebar */}
      {!isMobile && (
        <Box
          sx={{
            width: { md: 320, lg: 360 },
            borderRight: "1px solid #e0e0e0",
            display: "flex",
            flexDirection: "column",
            bgcolor: "white",
          }}
        >
          <AppBar
            position="static"
            sx={{
              background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
            }}
          >
            <Toolbar>
              <Lock sx={{ mr: 1 }} />
              <Typography variant="h6" sx={{ flexGrow: 1 }}>
                Secure Chat
              </Typography>
              <IconButton color="inherit" onClick={handleLogout}>
                <Logout />
              </IconButton>
            </Toolbar>
          </AppBar>
          <SidebarContent />
        </Box>
      )}

      {/* Mobile Drawer */}
      {isMobile && (
        <Drawer
          anchor="left"
          open={mobileDrawerOpen}
          onClose={() => setMobileDrawerOpen(false)}
          sx={{
            "& .MuiDrawer-paper": {
              width: 280,
            },
          }}
        >
          <AppBar
            position="static"
            sx={{
              background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
            }}
          >
            <Toolbar>
              <Lock sx={{ mr: 1 }} />
              <Typography variant="h6" sx={{ flexGrow: 1 }}>
                Secure Chat
              </Typography>
              <IconButton color="inherit" onClick={handleLogout}>
                <Logout />
              </IconButton>
            </Toolbar>
          </AppBar>
          <SidebarContent />
        </Drawer>
      )}

      {/* Main Chat Area */}
      <Box
        sx={{
          flexGrow: 1,
          display:
            isMobile && !showChatOnMobile && selectedUser ? "none" : "flex",
          flexDirection: "column",
          bgcolor: "#fafafa",
          width: isMobile ? "100%" : "auto",
        }}
      >
        {/* Mobile App Bar */}
        {isMobile && (
          <AppBar
            position="static"
            sx={{
              background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
            }}
          >
            <Toolbar>
              {selectedUser && showChatOnMobile ? (
                <IconButton
                  edge="start"
                  color="inherit"
                  onClick={handleBackToUsers}
                  sx={{ mr: 1 }}
                >
                  <ArrowBack />
                </IconButton>
              ) : (
                <IconButton
                  edge="start"
                  color="inherit"
                  onClick={() => setMobileDrawerOpen(true)}
                  sx={{ mr: 1 }}
                >
                  <MenuIcon />
                </IconButton>
              )}
              <Lock sx={{ mr: 1 }} />
              <Typography variant="h6" sx={{ flexGrow: 1 }}>
                {selectedUser && showChatOnMobile
                  ? selectedUser.username
                  : "Secure Chat"}
              </Typography>
              {!showChatOnMobile && (
                <IconButton color="inherit" onClick={handleLogout}>
                  <Logout />
                </IconButton>
              )}
            </Toolbar>
          </AppBar>
        )}

        {selectedUser ? (
          <>
            {/* Desktop Chat Header */}
            {!isMobile && (
              <Paper elevation={1} sx={{ p: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                  <Avatar sx={{ bgcolor: "#764ba2" }}>
                    {selectedUser.username.charAt(0).toUpperCase()}
                  </Avatar>
                  <Box>
                    <Typography variant="h6" fontWeight="bold">
                      {selectedUser.username}
                    </Typography>
                    <Box
                      sx={{ display: "flex", alignItems: "center", gap: 0.5 }}
                    >
                      <Lock
                        sx={{
                          fontSize: 14,
                          color: currentConversationKey ? "#10b981" : "#gray",
                        }}
                      />
                      <Typography
                        variant="caption"
                        color={
                          currentConversationKey
                            ? "success.main"
                            : "text.secondary"
                        }
                      >
                        {currentConversationKey
                          ? "End-to-end encrypted"
                          : "Loading encryption..."}
                      </Typography>
                    </Box>
                  </Box>
                </Box>
              </Paper>
            )}

            {/* Messages Container */}
            <Box
              sx={{
                flexGrow: 1,
                overflow: "auto",
                p: { xs: 1, sm: 2 },
                display: "flex",
                flexDirection: "column",
                gap: 1,
              }}
            >
              {loadingHistory && messages.length === 0 && (
                <Box
                  sx={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: 1,
                    py: 2,
                  }}
                >
                  <CircularProgress size={20} />
                  <Typography variant="body2" color="text.secondary">
                    Loading message history...
                  </Typography>
                </Box>
              )}

              {messages
                .filter((m) => m.senderId === selectedUser.userId || m.isOwn)
                .map((msg) => (
                  <Box
                    key={msg.id}
                    sx={{
                      display: "flex",
                      justifyContent: msg.isOwn ? "flex-end" : "flex-start",
                    }}
                  >
                    <Paper
                      elevation={1}
                      sx={{
                        maxWidth: { xs: "85%", sm: "70%" },
                        p: { xs: 1, sm: 1.5 },
                        bgcolor: msg.error
                          ? "#fee"
                          : msg.isOwn
                          ? "#667eea"
                          : "white",
                        color:
                          msg.isOwn && !msg.error ? "white" : "text.primary",
                        borderRadius: 2,
                        borderBottomRightRadius: msg.isOwn ? 4 : 16,
                        borderBottomLeftRadius: msg.isOwn ? 16 : 4,
                      }}
                    >
                      <Typography
                        variant="body1"
                        sx={{
                          wordBreak: "break-word",
                          fontSize: { xs: "0.9rem", sm: "1rem" },
                        }}
                      >
                        {msg.text}
                      </Typography>
                      <Box
                        sx={{
                          display: "flex",
                          alignItems: "center",
                          gap: 0.5,
                          mt: 0.5,
                          justifyContent: "flex-end",
                        }}
                      >
                        <Typography
                          variant="caption"
                          sx={{
                            opacity: 0.7,
                            fontSize: "0.7rem",
                          }}
                        >
                          {new Date(msg.timestamp).toLocaleTimeString()}
                        </Typography>
                        {msg.encrypted && !msg.error && (
                          <Lock sx={{ fontSize: 12, opacity: 0.7 }} />
                        )}
                      </Box>
                    </Paper>
                  </Box>
                ))}
              <div ref={messagesEndRef} />
            </Box>

            {error && (
              <Alert severity="error" sx={{ m: { xs: 1, sm: 2 }, mt: 0 }}>
                {error}
              </Alert>
            )}

            {/* Message Input */}
            <Paper
              component="form"
              onSubmit={handleSendMessage}
              sx={{
                p: { xs: 1, sm: 2 },
                display: "flex",
                gap: { xs: 0.5, sm: 1 },
                borderTop: "1px solid #e0e0e0",
              }}
            >
              <TextField
                fullWidth
                placeholder="Type a message..."
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                variant="outlined"
                size="small"
                disabled={!currentConversationKey}
                sx={{
                  "& .MuiOutlinedInput-root": {
                    fontSize: { xs: "0.9rem", sm: "1rem" },
                  },
                }}
              />
              <Button
                variant="contained"
                type="submit"
                disabled={!messageInput.trim() || !currentConversationKey}
                endIcon={!isMobile && <Send />}
                sx={{
                  background:
                    "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
                  "&:hover": {
                    background:
                      "linear-gradient(135deg, #5568d3 0%, #6a3f8f 100%)",
                  },
                  minWidth: { xs: "auto", sm: "100px" },
                  px: { xs: 2, sm: 3 },
                }}
              >
                {isMobile ? <Send /> : "Send"}
              </Button>
            </Paper>
          </>
        ) : (
          /* No Chat Selected */
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              height: "100%",
              p: 2,
            }}
          >
            <Card
              sx={{ maxWidth: { xs: "100%", sm: 400 }, textAlign: "center" }}
            >
              <CardContent sx={{ p: { xs: 2, sm: 4 } }}>
                <LockOpen
                  sx={{ fontSize: { xs: 48, sm: 64 }, color: "#667eea", mb: 2 }}
                />
                <Typography
                  variant="h5"
                  gutterBottom
                  fontWeight="bold"
                  sx={{ fontSize: { xs: "1.25rem", sm: "1.5rem" } }}
                >
                  Welcome to Secure Chat
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  {isMobile
                    ? "Tap the menu to select a user"
                    : "Select a user from the sidebar to start a secure conversation"}
                </Typography>

                <Divider sx={{ my: 2 }} />

                <Grid container spacing={1}>
                  <Grid item xs={12}>
                    <Chip
                      icon={<Lock />}
                      label="AES-256-CBC Encryption"
                      color="primary"
                      sx={{ width: "100%" }}
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <Chip
                      icon={<VerifiedUser />}
                      label="HMAC Message Integrity"
                      color="success"
                      sx={{ width: "100%" }}
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <Chip
                      icon={<Security />}
                      label="JWT Authentication"
                      color="secondary"
                      sx={{ width: "100%" }}
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <Chip
                      icon={<History />}
                      label="Persistent Message History"
                      color="info"
                      sx={{ width: "100%" }}
                    />
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Box>
        )}
      </Box>
    </Box>
  );
}

export default App;
