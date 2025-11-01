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
  Grid,
  IconButton,
  Badge,
  Alert,
  CircularProgress,
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
} from "@mui/icons-material";

const API_URL = "http://localhost:3000";

// ============= ENCRYPTION UTILITIES =============
const encryptMessage = (message, key) => {
  try {
    const iv = CryptoJS.lib.WordArray.random(16);
    const encrypted = CryptoJS.AES.encrypt(
      message,
      CryptoJS.enc.Hex.parse(key),
      {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      }
    );

    const encryptedHex = encrypted.ciphertext.toString(CryptoJS.enc.Hex);
    const ivHex = iv.toString(CryptoJS.enc.Hex);

    // Generate HMAC for integrity
    const hmac = CryptoJS.HmacSHA256(
      encryptedHex + ivHex,
      CryptoJS.enc.Hex.parse(key)
    );

    return {
      encrypted: encryptedHex,
      iv: ivHex,
      hmac: hmac.toString(CryptoJS.enc.Hex),
      timestamp: Date.now(),
    };
  } catch (error) {
    throw new Error("Encryption failed: " + error.message);
  }
};

const decryptMessage = (encryptedData, key) => {
  try {
    const { encrypted, iv, hmac: receivedHmac } = encryptedData;

    // Verify HMAC for integrity
    const calculatedHmac = CryptoJS.HmacSHA256(
      encrypted + iv,
      CryptoJS.enc.Hex.parse(key)
    );

    if (calculatedHmac.toString(CryptoJS.enc.Hex) !== receivedHmac) {
      throw new Error(
        "⚠️ Message integrity check failed - tampering detected!"
      );
    }

    // Decrypt message
    const decrypted = CryptoJS.AES.decrypt(
      { ciphertext: CryptoJS.enc.Hex.parse(encrypted) },
      CryptoJS.enc.Hex.parse(key),
      {
        iv: CryptoJS.enc.Hex.parse(iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      }
    );

    return decrypted.toString(CryptoJS.enc.Utf8);
  } catch (error) {
    throw new Error("Decryption failed: " + error.message);
  }
};

// ============= MAIN APP COMPONENT =============
function App() {
  // View state
  const [currentView, setCurrentView] = useState("login"); // 'login', 'register', 'chat'

  // Auth state
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [socket, setSocket] = useState(null);
  const [encryptionKey, setEncryptionKey] = useState(null);

  // Form state
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // Chat state
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [messages, setMessages] = useState([]);
  const [messageInput, setMessageInput] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  const messagesEndRef = useRef(null);

  // Auto-scroll to bottom
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // ============= AUTHENTICATION =============
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
  const connectSocket = (authToken, userData) => {
    const newSocket = io(API_URL, {
      auth: { token: authToken },
    });

    newSocket.on("connect", () => {
      console.log("✅ Connected to server");
      setCurrentView("chat");
      setSuccessMsg("");
    });

    newSocket.on("encryption-key", (data) => {
      console.log("🔑 Received encryption key");
      setEncryptionKey(data.key);
    });

    newSocket.on("users-online", (users) => {
      setOnlineUsers(users.filter((u) => u.userId !== userData.id));
    });

    newSocket.on("receive-message", (data) => {
      try {
        const decrypted = decryptMessage(data.encryptedMessage, encryptionKey);
        setMessages((prev) => [
          ...prev,
          {
            id: Date.now(),
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
            id: Date.now(),
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

    newSocket.on("message-sent", () => {
      console.log("✅ Message delivered");
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
  };

  // ============= SEND MESSAGE =============
  const handleSendMessage = (e) => {
    e.preventDefault();

    if (!messageInput.trim() || !selectedUser || !encryptionKey) return;

    try {
      const encrypted = encryptMessage(messageInput, encryptionKey);

      socket.emit("send-message", {
        encryptedMessage: encrypted,
        recipientId: selectedUser.userId,
        recipientUsername: selectedUser.username,
      });

      // Add to local messages
      setMessages((prev) => [
        ...prev,
        {
          id: Date.now(),
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

  const handleLogout = () => {
    if (socket) {
      socket.disconnect();
    }
    setSocket(null);
    setUser(null);
    setToken(null);
    setEncryptionKey(null);
    setCurrentView("login");
    setMessages([]);
    setSelectedUser(null);
    setUsername("");
    setPassword("");
  };

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
          p: 2,
        }}
      >
        <Paper elevation={10} sx={{ p: 4, maxWidth: 400, width: "100%" }}>
          <Box sx={{ textAlign: "center", mb: 3 }}>
            <Lock sx={{ fontSize: 48, color: "#667eea", mb: 1 }} />
            <Typography variant="h4" fontWeight="bold" gutterBottom>
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
  return (
    <Box sx={{ display: "flex", height: "100vh", bgcolor: "#f5f5f5" }}>
      {/* Sidebar */}
      <Box
        sx={{
          width: 320,
          bgcolor: "white",
          borderRight: "1px solid #e0e0e0",
          display: "flex",
          flexDirection: "column",
        }}
      >
        {/* Header */}
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

        {/* Current User */}
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

          {encryptionKey && (
            <Chip
              icon={<Lock />}
              label="Encryption Active"
              size="small"
              color="success"
              sx={{ mt: 1 }}
            />
          )}
        </Paper>

        <Divider />

        {/* Online Users List */}
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
                button
                selected={selectedUser?.userId === u.userId}
                onClick={() => setSelectedUser(u)}
                sx={{
                  borderRadius: 1,
                  mb: 0.5,
                  "&.Mui-selected": {
                    bgcolor: "#e3f2fd",
                    "&:hover": { bgcolor: "#bbdefb" },
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

      {/* Main Chat Area */}
      <Box
        sx={{
          flexGrow: 1,
          display: "flex",
          flexDirection: "column",
          bgcolor: "#fafafa",
        }}
      >
        {selectedUser ? (
          <>
            {/* Chat Header */}
            <Paper elevation={1} sx={{ p: 2 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                <Avatar sx={{ bgcolor: "#764ba2" }}>
                  {selectedUser.username.charAt(0).toUpperCase()}
                </Avatar>
                <Box>
                  <Typography variant="h6" fontWeight="bold">
                    {selectedUser.username}
                  </Typography>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                    <Lock sx={{ fontSize: 14, color: "#10b981" }} />
                    <Typography variant="caption" color="success.main">
                      End-to-end encrypted
                    </Typography>
                  </Box>
                </Box>
              </Box>
            </Paper>

            {/* Messages Container */}
            <Box
              sx={{
                flexGrow: 1,
                overflow: "auto",
                p: 2,
                display: "flex",
                flexDirection: "column",
                gap: 1,
              }}
            >
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
                        maxWidth: "70%",
                        p: 1.5,
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
                        sx={{ wordBreak: "break-word" }}
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

            {/* Error Alert */}
            {error && (
              <Alert severity="error" sx={{ m: 2, mt: 0 }}>
                {error}
              </Alert>
            )}

            {/* Message Input */}
            <Paper
              component="form"
              onSubmit={handleSendMessage}
              sx={{
                p: 2,
                display: "flex",
                gap: 1,
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
                disabled={!encryptionKey}
              />
              <Button
                variant="contained"
                type="submit"
                disabled={!messageInput.trim() || !encryptionKey}
                endIcon={<Send />}
                sx={{
                  background:
                    "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
                  "&:hover": {
                    background:
                      "linear-gradient(135deg, #5568d3 0%, #6a3f8f 100%)",
                  },
                }}
              >
                Send
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
            }}
          >
            <Card sx={{ maxWidth: 400, textAlign: "center" }}>
              <CardContent sx={{ p: 4 }}>
                <LockOpen sx={{ fontSize: 64, color: "#667eea", mb: 2 }} />
                <Typography variant="h5" gutterBottom fontWeight="bold">
                  Welcome to Secure Chat
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Select a user from the sidebar to start a secure conversation
                </Typography>

                <Divider sx={{ my: 2 }} />

                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  <Chip
                    icon={<Lock />}
                    label="AES-256-CBC Encryption"
                    color="primary"
                  />
                  <Chip
                    icon={<VerifiedUser />}
                    label="HMAC Message Integrity"
                    color="success"
                  />
                  <Chip
                    icon={<Security />}
                    label="JWT Authentication"
                    color="secondary"
                  />
                </Box>
              </CardContent>
            </Card>
          </Box>
        )}
      </Box>
    </Box>
  );
}

export default App;
