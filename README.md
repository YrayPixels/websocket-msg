# WebSocket Chat Server - Laravel Backend Integration

**⚠️ IMPORTANT: This websocket server now uses Laravel backend exclusively for data storage and encryption. Local SQLite database has been removed.**

## Overview

This WebSocket server provides real-time messaging capabilities and integrates directly with a Laravel backend for:
- **Message Storage**: All messages are stored in Laravel database with automatic encryption
- **User Authentication**: Uses Laravel Sanctum tokens for authentication
- **Encryption**: Handled automatically by Laravel using custom encrypted casts
- **Chat Management**: Private chats and rooms managed through Laravel API

## Key Changes from SQLite Version

### ✅ What's New:
- **Laravel Backend Integration**: All data operations go through Laravel API
- **Automatic Encryption**: Laravel handles encryption/decryption using EncryptedContent and EncryptedArray casts
- **Simplified Architecture**: No local database, no local encryption logic
- **Real-time + Persistent**: WebSocket for real-time communication, Laravel for persistence

### ❌ What's Removed:
- Local SQLite database
- Local encryption/decryption functions
- Room key management
- Local chat history storage

## Architecture

```
Client <-> WebSocket Server (192.168.106.235:3001) <-> Laravel Backend API (192.168.106.235:8000) <-> MySQL Database
                                                     (with encrypted storage)
```

## Setup

### Prerequisites
- Node.js
- Running Laravel backend with chat API endpoints
- Laravel backend with proper encryption setup

### Environment Variables
```bash
LARAVEL_API_URL=http://192.168.106.235:8000/api  # Your Laravel backend URL
PORT=3001                                       # WebSocket server port
HOST=0.0.0.0                                   # Listen on all interfaces for network access
```

### Installation
```bash
npm install
node server.js
```

## Laravel Backend Requirements

Your Laravel backend must have these API endpoints:

### Chat Messages API
- `POST /api/chat-messages` - Store new messages
- `GET /api/chat-messages/{chatId}` - Get messages for a chat
- `PUT /api/chat-messages/{messageId}/status` - Update message status
- `POST /api/chat-messages/search` - Search messages
- `GET /api/user/{username}/chats` - Get user's chats
- `GET /api/chat-rooms` - Get all chat rooms

### Authentication API
- `GET /api/user` - Validate Sanctum token and get user info

## Message Flow

1. **Sending Messages**:
   - Client sends message via WebSocket
   - Server stores message in Laravel (encrypted automatically)
   - Server broadcasts message to relevant clients
   - Message stored with encryption in Laravel database

2. **Retrieving Messages**:
   - Client requests chat history via HTTP API
   - Server fetches from Laravel API (auto-decrypted)
   - Server returns decrypted messages to client

3. **File Uploads**:
   - Files uploaded to websocket server
   - File metadata stored in Laravel (encrypted)
   - Files served directly from websocket server

## WebSocket Events

### Client -> Server
- `join-room` - Join a chat room
- `send-message` - Send message to room
- `private-message` - Send private message
- `mark-message-read` - Mark message as read
- `typing-start/stop` - Typing indicators

### Server -> Client
- `new-message` - New message received
- `private-message` - Private message received
- `message-read` - Message read confirmation
- `user-typing` - Typing indicators

## Security

- **Authentication**: Laravel Sanctum tokens required
- **Encryption**: All sensitive data encrypted in Laravel database
- **File Security**: Files served through controlled endpoints

## Development Notes

- All encryption is handled by Laravel backend using `EncryptedContent` and `EncryptedArray` casts
- WebSocket server maintains active connections but doesn't store chat data
- Message history is fetched from Laravel API when needed
- File uploads stored locally but metadata encrypted in Laravel

## Migration from SQLite Version

If migrating from the SQLite version:
1. Ensure Laravel backend is set up with encryption casts
2. Update client applications to use new API structure
3. Remove any local database files
4. Update environment variables to point to Laravel backend 