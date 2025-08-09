const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const mime = require('mime-types');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
// Remove SQLite database dependency - now using Laravel backend exclusively
// const ChatDatabase = require('./database');

// Import fetch for Node.js compatibility
const nodeFetch = require('node-fetch');
if (typeof globalThis.fetch === 'undefined') {
  globalThis.fetch = nodeFetch;
}

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '0.0.0.0'; // Listen on all interfaces to allow external connections

// Laravel backend URL - adjust this to match your Laravel setup
const LARAVEL_API_URL = process.env.LARAVEL_API_URL || 'http://192.168.106.235:8000/api';


// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const extension = path.extname(file.originalname);
    cb(null, `${uniqueSuffix}${extension}`);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Allow common file types
    const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt|zip|rar|mp4|mov|avi|mp3|wav/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only images, documents, videos, and audio files are allowed.'));
    }
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Store active websocket connections and rooms (encryption handled by Laravel backend)
const activeUsers = new Map();
const chatRooms = new Map();
const roomKeys = new Map(); // Store room encryption keys

// Database wrapper to interface with Laravel backend
const database = {
  async createOrGetChat(type, participants, roomName = null) {
    try {
      // For rooms, create a consistent chat ID
      const chatId = type === 'room' ? `room-${roomName}` : `private-${participants.sort().join('-')}`;
      
      return {
        id: chatId,
        type: type,
        participants: participants,
        roomName: roomName,
        created_at: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error creating/getting chat:', error);
      throw error;
    }
  },

  async getMessages(chatId, limit = 50) {
    try {
      const result = await getMessagesFromLaravel(chatId, limit);
      
      if (result.success && result.data) {
        return result.data.map(msg => ({
          id: msg.message_id,
          type: msg.message_type,
          text: msg.content,
          sender: {
            username: msg.sender_username
          },
          timestamp: msg.sent_at,
          status: msg.status,
          encrypted: msg.encrypted || false,
          file: msg.file_metadata
        }));
      }
      
      return [];
    } catch (error) {
      console.error('Error getting messages:', error);
      return [];
    }
  }
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/rooms', (req, res) => {
  const rooms = Array.from(chatRooms.keys());
  res.json(rooms);
});

app.get('/api/users/:roomId', (req, res) => {
  const { roomId } = req.params;
  const room = chatRooms.get(roomId);
  if (room) {
    res.json(Array.from(room.users.values()));
  } else {
    res.json([]);
  }
});

// Get all online users for private messaging
app.get('/api/online-users', (req, res) => {
  const { currentUser } = req.query;
  const onlineUsers = Array.from(activeUsers.values())
    .filter(user => user.username !== currentUser)
    .map(user => ({
      id: user.id,
      username: user.username,
      room: user.room,
      joinedAt: user.joinedAt
    }));
  res.json(onlineUsers);
});

// Get private chat history between two users
app.get('/api/private-chat/:user1/:user2', async (req, res) => {
  const { user1, user2 } = req.params;
  const { requestingUser } = req.query;
  
  try {
    // Verify the requesting user is one of the participants
    if (requestingUser !== user1 && requestingUser !== user2) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Create chat ID
    const participants = [user1, user2].sort();
    const chatId = `private-${participants.join('-')}`;
    
    // Get messages from Laravel backend (automatically decrypted)
    const result = await getMessagesFromLaravel(chatId, 100);
    if (!result.success) {
      console.error('Error getting messages from Laravel:', result.error);
      return res.status(500).json({ error: 'Failed to get chat history' });
    }
    
    const messages = result.data.map(msg => ({
      id: msg.message_id,
      type: msg.message_type,
      text: msg.content, // Already decrypted by Laravel
      sender: {
        username: msg.sender_username
      },
      timestamp: msg.sent_at,
      status: msg.status,
      delivered: msg.status === 'delivered' || msg.status === 'read',
      read: msg.status === 'read',
      deliveredAt: msg.delivered_at,
      readAt: msg.read_at
    }));
    
    console.log(`=== Retrieved ${messages.length} messages for chat ${chatId} from Laravel ===`);
    res.json(messages);
  } catch (error) {
    console.error('Error getting private chat history:', error);
    res.status(500).json({ error: 'Failed to get chat history' });
  }
});

// Remove room encryption key endpoint - encryption now handled by Laravel backend

// File upload endpoint
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { room, username } = req.body;
    
    if (!room || !username) {
      return res.status(400).json({ error: 'Room and username are required' });
    }

    const fileInfo = {
      id: uuidv4(),
      filename: req.file.filename,
      originalName: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      url: `/uploads/${req.file.filename}`,
      uploadedAt: new Date()
    };

    // Check if file is an image
    const isImage = req.file.mimetype.startsWith('image/');

    try {
      // Create chat ID for the room
      const chatId = `room-${room}`;
      
      // Generate unique message ID
      const messageId = uuidv4();
      
      // Get all participants in the room (if room exists in memory)
      const roomParticipants = Array.from(chatRooms.get(room)?.users.values() || [])
        .map(roomUser => roomUser.username);
      
      // Store file message in Laravel database (with encryption handled by Laravel)
      const laravelMessageData = {
        message_id: messageId,
        chat_id: chatId,
        chat_type: 'room',
        sender_username: username,
        message_type: 'file',
        content: `File: ${fileInfo.originalName}`, // Description of the file
        file_metadata: {
          filename: fileInfo.filename,
          originalName: fileInfo.originalName,
          mimetype: fileInfo.mimetype,
          size: fileInfo.size,
          url: fileInfo.url,
          uploadedAt: fileInfo.uploadedAt,
          isImage: isImage
        },
        status: 'sent',
        encrypted: true,
        room_name: room,
        participants: roomParticipants,
        sent_at: new Date().toISOString()
      };
      
      // Store in Laravel (blocking to ensure message is stored)
      const storeResult = await storeChatMessageInLaravel(laravelMessageData);
      if (!storeResult.success) {
        console.error('Failed to store file message in Laravel:', storeResult.error);
        throw new Error('Failed to store file message');
      }
      
      // Create message for broadcasting
      const broadcastMessage = {
        id: messageId,
        type: 'file',
        file: {
          ...fileInfo,
          isImage: isImage
        },
        isImage: isImage,
        sender: {
          username: username
        },
        timestamp: new Date(),
        chatId: chatId
      };
      
      // Broadcast file message to all users in the room
      io.to(room).emit('new-message', broadcastMessage);
      
    } catch (dbError) {
      console.error('File storage error:', dbError);
      return res.status(500).json({ error: 'Failed to store file message' });
    }

    res.json({ 
      success: true, 
      file: fileInfo
    });
  } catch (error) {
    console.error('File upload error:', error);
    res.status(500).json({ error: 'File upload failed' });
  }
});

// File view endpoint for direct file access
app.get('/api/file-view/:filename', async (req, res) => {
  try {
    const filename = req.params.filename;
    const filePath = path.join(uploadsDir, filename);
    
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    // Get file mime type
    const mimeType = mime.lookup(filePath) || 'application/octet-stream';
    
    // Set appropriate headers
    res.setHeader('Content-Type', mimeType);
    res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
    
    // Stream the file directly
    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);
    
  } catch (error) {
    console.error('File view error:', error);
    res.status(500).json({ error: 'File view failed' });
  }
});

// File download endpoint for direct file download
app.get('/api/download/:filename', async (req, res) => {
  try {
    const filename = req.params.filename;
    const filePath = path.join(uploadsDir, filename);
    
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    // Get file mime type
    const mimeType = mime.lookup(filePath) || 'application/octet-stream';
    
    // Set download headers
    res.setHeader('Content-Type', mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    
    // Stream the file directly
    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);
    
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Download failed' });
  }
});

// Socket.io connection handling
io.use(async (socket, next) => {
  const { token, userId, username, email, laravelAuth } = socket.handshake.auth;
  
  console.log('Authentication attempt:', {
    username,
    userId,
    email,
    hasToken: !!token,
    laravelAuth,
    socketId: socket.id
  });

  // If Laravel authentication is requested and token is provided
  if (laravelAuth && token) {
    try {
      const validation = await validateSanctumToken(token);
      if (validation.success) {
        socket.user = {
          id: validation.user.id || userId,
          username: validation.user.name || username,
          email: validation.user.email || email,
          authenticated: true,
          authMethod: 'laravel'
        };
        console.log('Laravel authentication successful for:', socket.user.username);
        return next();
      } else {
        console.log('Laravel authentication failed:', validation.error);
        // Fall back to basic authentication
      }
    } catch (error) {
      console.error('Laravel authentication error:', error);
      // Fall back to basic authentication
    }
  }

  // Basic authentication (no Laravel backend required)
  if (username && userId && email) {
    socket.user = {
      id: userId,
      username: username,
      email: email,
      authenticated: true,
      authMethod: 'basic'
    };
    console.log('Basic authentication successful for:', socket.user.username);
    return next();
  }

  // Authentication failed
  console.log('Authentication failed: Missing required credentials');
  const error = new Error('Authentication failed: Username, userId, and email are required');
  error.data = { message: 'Missing authentication credentials' };
  next(error);
});

io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);
  console.log('User info:', socket.user);

  // Handle joining a room
  socket.on('join', async ({ username, room }) => {
    try {
      // Validate user matches socket auth
      if (socket.user.username !== username) {
        console.warn('Username mismatch:', socket.user.username, 'vs', username);
        socket.emit('auth_error', { message: 'Username mismatch' });
        return;
      }

      const user = {
        id: socket.user.id,
        username: socket.user.username,
        email: socket.user.email,
        socketId: socket.id,
        room: room,
        joinedAt: new Date(),
        authMethod: socket.user.authMethod
      };

      // Add user to active users
      activeUsers.set(socket.id, user);

      // Join the socket room
      socket.join(room);

      // Add user to room tracking
      if (!chatRooms.has(room)) {
        chatRooms.set(room, {
          users: new Map(),
          createdAt: new Date()
        });
        
        // Generate encryption key for new room
        roomKeys.set(room, generateRoomKey());
      }

      const roomData = chatRooms.get(room);
      roomData.users.set(socket.id, user);

      console.log(`${username} joined room: ${room} (${socket.user.authMethod} auth)`);

      // Notify room about new user
      socket.to(room).emit('user-joined', {
        user: {
          id: user.id,
          username: user.username,
          joinedAt: user.joinedAt
        },
        message: `${username} joined the chat`
      });

      // Send current room users to the new user
      const roomUsers = Array.from(roomData.users.values()).map(u => ({
        id: u.id,
        username: u.username,
        joinedAt: u.joinedAt
      }));
      
      socket.emit('room-users', roomUsers);

      // Send recent messages from the room
      try {
        // Create or get room chat in database  
        const chatRoom = await database.createOrGetChat('room', [username], room);
        const recentMessages = await database.getMessages(chatRoom.id, 50);
        const roomKey = roomKeys.get(room);
        
        if (roomKey && recentMessages.length > 0) {
          const decryptedMessages = recentMessages.map(msg => decryptMessage(msg, roomKey));
          socket.emit('recent-messages', decryptedMessages);
        } else {
          socket.emit('recent-messages', recentMessages);
        }
        
        console.log(`Sent ${recentMessages.length} recent messages to ${username} in room ${room}`);
      } catch (error) {
        console.error('Error fetching recent messages:', error);
        socket.emit('recent-messages', []);
      }

    } catch (error) {
      console.error('Error in join handler:', error);
      socket.emit('error', { message: 'Failed to join room' });
    }
  });

  // Handle sending messages
  socket.on('send-message', async (data) => {
    const user = activeUsers.get(socket.id);
    if (!user || !socket.user) {
      socket.emit('error', { message: 'User not authenticated' });
      return;
    }
    
    try {
      // Create chat ID for the room
      const chatId = `room-${user.room}`;
      
      // Generate unique message ID
      const messageId = uuidv4();
      
      // Get all participants in the room
      const roomParticipants = Array.from(chatRooms.get(user.room)?.users.values() || [])
        .map(roomUser => roomUser.username);
      
      // Store message directly in Laravel database (with encryption handled by Laravel)
      const laravelMessageData = {
        message_id: messageId,
        chat_id: chatId,
        chat_type: 'room',
        sender_username: socket.user.username,
        message_type: 'text',
        content: data.text,
        status: 'sent',
        encrypted: true,
        room_name: user.room,
        participants: roomParticipants,
        sent_at: new Date().toISOString()
      };
      
      // Store in Laravel (blocking to ensure message is stored before broadcasting)
      const storeResult = await storeChatMessageInLaravel(laravelMessageData);
      if (!storeResult.success) {
        console.error('Failed to store message in Laravel:', storeResult.error);
        socket.emit('error', { message: 'Failed to send message' });
        return;
      }
      
      // Create message object for broadcasting
      const message = {
        id: messageId,
        type: 'text',
        text: data.text,
        sender: {
          id: socket.user.id,
          username: socket.user.username
        },
        timestamp: new Date(),
        chatId: chatId
      };
      
      // Broadcast message to all users in the room
      io.to(user.room).emit('new-message', message);
      
      console.log(`Message stored in Laravel and broadcast in ${user.room} from ${socket.user.username}`);
    } catch (error) {
      console.error('Error handling send message:', error);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  // Handle typing indicators
  socket.on('typing-start', () => {
    const user = activeUsers.get(socket.id);
    if (user) {
      socket.to(user.room).emit('user-typing', {
        username: user.username,
        isTyping: true
      });
    }
  });

  socket.on('typing-stop', () => {
    const user = activeUsers.get(socket.id);
    if (user) {
      socket.to(user.room).emit('user-typing', {
        username: user.username,
        isTyping: false
      });
    }
  });

  // Handle private messages
  socket.on('private-message', async (data) => {
    const { recipientUsername, text } = data;
    const sender = activeUsers.get(socket.id);
    
    if (!sender || !socket.user) {
      socket.emit('error', { message: 'User not authenticated' });
      return;
    }
    
    try {
      // Find recipient by username
      const recipient = Array.from(activeUsers.values()).find(user => user.username === recipientUsername);
      console.log(`Private message attempt: ${socket.user.username} -> ${recipientUsername}, recipient found: ${!!recipient}`);
      
      // Create chat ID for private conversation
      const participants = [socket.user.username, recipientUsername].sort();
      const chatId = `private-${participants.join('-')}`;
      console.log(`Private chat ID: ${chatId}`);
      
      // Generate unique message ID
      const messageId = uuidv4();
      console.log(`Generated message ID: ${messageId}`);
      
      // Store message directly in Laravel database (with encryption handled by Laravel)
      const laravelMessageData = {
        message_id: messageId,
        chat_id: chatId,
        chat_type: 'private',
        sender_username: socket.user.username,
        message_type: 'text',
        content: text,
        status: 'sent',
        encrypted: true,
        room_name: null,
        participants: [socket.user.username, recipientUsername],
        sent_at: new Date().toISOString()
      };
      
      // Store in Laravel (blocking to ensure message is stored before proceeding)
      const storeResult = await storeChatMessageInLaravel(laravelMessageData);
      if (!storeResult.success) {
        console.error('Failed to store private message in Laravel:', storeResult.error);
        socket.emit('private-message-error', { error: 'Failed to send private message' });
        return;
      }
      
      // Create message object
      const message = {
        id: messageId,
        type: 'private',
        text: text,
        sender: {
          id: socket.user.id,
          username: socket.user.username
        },
        recipient: {
          id: recipient ? recipient.id : 'unknown',
          username: recipientUsername
        },
        timestamp: new Date(),
        chatId: chatId
      };
      
      // Send to recipient if online
      if (recipient) {
        io.to(recipient.socketId).emit('private-message', message);
        
        // Update status to delivered in Laravel (non-blocking)
        updateMessageStatusInLaravel(messageId, 'delivered').catch(error => {
          console.error('Failed to update message status in Laravel:', error);
        });
        
        // Also update the message object to show delivered status
        message.delivered = true;
        message.deliveredAt = new Date();
      }
      
      // Send confirmation to sender
      socket.emit('private-message-sent', message);
      
      console.log(`Private message from ${socket.user.username} to ${recipientUsername} stored in Laravel`);
    } catch (error) {
      console.error('Error handling private message:', error);
      socket.emit('private-message-error', { error: 'Failed to send private message' });
    }
  });

  // Handle private typing indicators
  socket.on('private-typing-start', (data) => {
    const { recipientUsername } = data;
    const sender = activeUsers.get(socket.id);
    
    if (sender) {
      const recipient = Array.from(activeUsers.values()).find(user => user.username === recipientUsername);
      if (recipient) {
        io.to(recipient.socketId).emit('private-typing', {
          from: sender.username,
          isTyping: true
        });
      }
    }
  });

  socket.on('private-typing-stop', (data) => {
    const { recipientUsername } = data;
    const sender = activeUsers.get(socket.id);
    
    if (sender) {
      const recipient = Array.from(activeUsers.values()).find(user => user.username === recipientUsername);
      if (recipient) {
        io.to(recipient.socketId).emit('private-typing', {
          from: sender.username,
          isTyping: false
        });
      }
    }
  });

  // Handle marking messages as read
  socket.on('mark-message-read', async (data) => {
    const { messageId, senderUsername, readAt } = data;
    const user = activeUsers.get(socket.id);
    
    if (!user) return;
    
    try {
      // Update status in Laravel (blocking to ensure consistency)
      const updateResult = await updateMessageStatusInLaravel(messageId, 'read', readAt);
      if (!updateResult.success) {
        console.error('Failed to update message read status in Laravel:', updateResult.error);
        return;
      }
      
      // Notify the sender that their message was read
      const sender = Array.from(activeUsers.values()).find(u => u.username === senderUsername);
      if (sender) {
        io.to(sender.socketId).emit('message-read', {
          messageId,
          readerUsername: user.username,
          readAt
        });
      }
      
      console.log(`Message ${messageId} marked as read by ${user.username} in Laravel`);
    } catch (error) {
      console.error('Error marking message as read:', error);
    }
  });

  // Handle user disconnection
  socket.on('disconnect', () => {
    const user = activeUsers.get(socket.id);
    
    if (user) {
      // Remove user from room
      const room = chatRooms.get(user.room);
      if (room) {
        room.users.delete(socket.id);
        
        // Notify room about user leaving
        socket.to(user.room).emit('user-left', {
          user: {
            id: user.id,
            username: user.username
          },
          message: `${user.username} left the chat`
        });
        
                  // Remove empty rooms and their keys
          if (room.users.size === 0) {
            chatRooms.delete(user.room);
            roomKeys.delete(user.room); // Clean up encryption key
          }
      }
      
      activeUsers.delete(socket.id);
      console.log(`${user.username} disconnected from room: ${user.room}`);
    }
    
    console.log('Client disconnected:', socket.id);
  });

  // Handle errors
  socket.on('error', (error) => {
    console.error('Socket error:', error);
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server with database initialization
const startServer = async () => {
  try {
    // await initDatabase(); // Removed local database initialization
    server.listen(PORT, HOST, () => {
      console.log(`WebSocket chat server running on http://${HOST}:${PORT}`);
      console.log(`Visit http://192.168.106.235:${PORT} to test the chat`);
      console.log(`Server accessible from network at http://192.168.106.235:${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down server...');
  
  // Close database connection
  // if (database) { // Removed local database close
  //   database.close();
  //   console.log('Database connection closed');
  // }
  
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

// Helper function to generate room encryption keys (legacy compatibility)
function generateRoomKey() {
  return crypto.randomBytes(32).toString('hex');
}

// Helper function to encrypt text (legacy compatibility)
function encrypt(text, key) {
  try {
    const cipher = crypto.createCipher('aes-256-cbc', key);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  } catch (error) {
    console.error('Encryption error:', error);
    return null;
  }
}

// Helper function to decrypt text (legacy compatibility)
function decrypt(encryptedData, key) {
  try {
    // Handle both string and object inputs
    const encrypted = typeof encryptedData === 'object' ? encryptedData.encrypted : encryptedData;
    
    if (!encrypted || typeof encrypted !== 'string') {
      return encryptedData; // Return original if not encrypted
    }
    
    const decipher = crypto.createDecipher('aes-256-cbc', key);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    return encryptedData; // Return original on error
  }
}

// Helper function to decrypt messages for client consumption (legacy compatibility)
function decryptMessage(message, roomKey) {
  if (!message.encrypted) {
    return message; // Return as-is if not encrypted
  }
  
  const decryptedMessage = { ...message };
  
  if (message.type === 'text') {
    const decryptedText = decrypt(message.text, roomKey);
    if (decryptedText) {
      decryptedMessage.text = decryptedText;
      delete decryptedMessage.encrypted;
    }
  } else if (message.type === 'file' && message.file.originalName) {
    // Check if originalName is an encrypted object or already a string
    let decryptedName;
    if (typeof message.file.originalName === 'object') {
      decryptedName = decrypt(message.file.originalName, roomKey);
    } else {
      decryptedName = message.file.originalName; // Already decrypted
    }
    
    if (decryptedName) {
      decryptedMessage.file = { ...message.file };
      decryptedMessage.file.originalName = decryptedName;
      // For images, update the URL to use the decrypted view endpoint
      if (decryptedMessage.isImage && message.file.decryptedUrl) {
        decryptedMessage.file.url = message.file.decryptedUrl;
      }
      // Keep encryption metadata for file downloads but remove from display
      delete decryptedMessage.encrypted;
    }
  }
  
  return decryptedMessage;
}

// Helper function to decrypt private messages (legacy compatibility)
function decryptPrivateMessage(message, chatKey) {
  if (!message.encrypted || message.type !== 'private') {
    return message; // Return as-is if not encrypted or not private
  }
  
  const decryptedMessage = { ...message };
  const decryptedText = decrypt(message.text, chatKey);
  
  if (decryptedText) {
    decryptedMessage.text = decryptedText;
    delete decryptedMessage.encrypted;
  }
  
  return decryptedMessage;
}

// Token validation middleware
const validateSanctumToken = async (token) => {
  try {
    const response = await fetch(`${LARAVEL_API_URL}/user`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      }
    });

    if (response.ok) {
      const userData = await response.json();
      return {
        success: true,
        user: userData
      };
    } else {
      return {
        success: false,
        error: 'Invalid token'
      };
    }
  } catch (error) {
    console.error('Token validation error:', error);
    return {
      success: false,
      error: 'Token validation failed'
    };
  }
};

// Laravel integration functions
const storeChatMessageInLaravel = async (messageData) => {
  try {
    const response = await fetch(`${LARAVEL_API_URL}/chat-messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(messageData)
    });

    if (!response.ok) {
      const errorData = await response.json();
      console.error('Laravel API error:', errorData);
      return { success: false, error: errorData };
    }

    const result = await response.json();
    console.log('Message stored in Laravel:', result);
    return { success: true, data: result };
  } catch (error) {
    console.error('Error storing message in Laravel:', error);
    return { success: false, error: error.message };
  }
};

const updateMessageStatusInLaravel = async (messageId, status, timestamp) => {
  try {
    const response = await fetch(`${LARAVEL_API_URL}/chat-messages/${messageId}/status`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        status: status,
        timestamp: timestamp || new Date().toISOString()
      })
    });

    if (!response.ok) {
      const errorData = await response.json();
      console.error('Laravel status update error:', errorData);
      return { success: false, error: errorData };
    }

    const result = await response.json();
    return { success: true, data: result };
  } catch (error) {
    console.error('Error updating message status in Laravel:', error);
    return { success: false, error: error.message };
  }
};

// Get messages from Laravel backend
const getMessagesFromLaravel = async (chatId, limit = 50, offset = 0) => {
  try {
    const response = await fetch(`${LARAVEL_API_URL}/chat-messages/${encodeURIComponent(chatId)}?limit=${limit}&offset=${offset}`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      }
    });

    if (!response.ok) {
      const errorData = await response.json();
      console.error('Laravel get messages error:', errorData);
      return { success: false, error: errorData };
    }

    const result = await response.json();
    return { success: true, data: result.data || [] };
  } catch (error) {
    console.error('Error getting messages from Laravel:', error);
    return { success: false, error: error.message, data: [] };
  }
};

// Get user chats from Laravel backend
const getUserChatsFromLaravel = async (username) => {
  try {
    const response = await fetch(`${LARAVEL_API_URL}/user/${encodeURIComponent(username)}/chats`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      }
    });

    if (!response.ok) {
      const errorData = await response.json();
      console.error('Laravel get user chats error:', errorData);
      return { success: false, error: errorData };
    }

    const result = await response.json();
    return { success: true, data: result.data || [] };
  } catch (error) {
    console.error('Error getting user chats from Laravel:', error);
    return { success: false, error: error.message, data: [] };
  }
};

// Get chat rooms from Laravel backend
const getChatRoomsFromLaravel = async () => {
  try {
    const response = await fetch(`${LARAVEL_API_URL}/chat-rooms`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      }
    });

    if (!response.ok) {
      const errorData = await response.json();
      console.error('Laravel get chat rooms error:', errorData);
      return { success: false, error: errorData };
    }

    const result = await response.json();
    return { success: true, data: result.data || [] };
  } catch (error) {
    console.error('Error getting chat rooms from Laravel:', error);
    return { success: false, error: error.message, data: [] };
  }
};

// Search messages in Laravel backend
const searchMessagesInLaravel = async (searchTerm, chatId = null, chatType = null, limit = 20) => {
  try {
    const response = await fetch(`${LARAVEL_API_URL}/chat-messages/search`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        search_term: searchTerm,
        chat_id: chatId,
        chat_type: chatType,
        limit: limit
      })
    });

    if (!response.ok) {
      const errorData = await response.json();
      console.error('Laravel search messages error:', errorData);
      return { success: false, error: errorData };
    }

    const result = await response.json();
    return { success: true, data: result.data || [] };
  } catch (error) {
    console.error('Error searching messages in Laravel:', error);
    return { success: false, error: error.message, data: [] };
  }
}; 