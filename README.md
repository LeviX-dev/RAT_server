# Advanced Socket Server (Node.js)

A Node.js implementation of a multithreaded socket server with authentication, JSON message handling, and file operations.

## Features

- **Multi-client Support**: Accepts multiple concurrent client connections
- **Authentication**: SHA-256 based authentication using pre-shared secret key
- **JSON Message Handling**: Processes structured JSON messages from clients
- **Screenshot Handling**: Decodes and saves base64-encoded screenshots
- **Command Interface**: Interactive CLI for sending commands to clients
- **Comprehensive Logging**: Console and file-based logging with timestamps
- **Error Handling**: Robust error handling for connections, timeouts, and exceptions
- **Clean Shutdown**: Graceful server shutdown with proper cleanup

## Message Types

The server handles the following message types from clients:

- `{ "output": "..." }`: Logs command output
- `{ "error": "..." }`: Logs error messages
- `{ "screenshot": "base64..." }`: Decodes and saves screenshots

## Usage

### Starting the Server

```bash
# Install dependencies (none required - uses Node.js built-in modules)
npm start

# Or run directly
node server.js
```

### Server Commands

Once the server is running, you can use the following commands:

- `client_id|command`: Send a command to a specific client
- `list`: Show all connected clients and their status
- `exit` or `quit`: Stop the server

### Example Commands

```
Client1|dir
Client2|whoami
Client3|screenshot
list
exit
```

## Configuration

Edit the constants at the top of `server.js` to customize:

- `SERVER_IP`: Server IP address (default: 127.0.0.1)
- `SERVER_PORT`: Server port (default: 4444)
- `SECRET_KEY`: Authentication secret key
- `MAX_CLIENTS`: Maximum number of concurrent clients
- `CONNECTION_TIMEOUT`: Client connection timeout in milliseconds

## File Structure

```
server/
├── server.js          # Main server implementation
├── package.json       # Node.js project configuration
├── README.md         # This file
├── downloads/        # Screenshots and downloaded files
├── uploads/          # Uploaded files from clients
└── server_enhanced.log # Server log file
```

## Key Differences from Python Version

### Async vs Threading
- **Python**: Uses `threading` module for concurrent client handling
- **Node.js**: Uses event-driven async model with `net` module

### Select Equivalent
- **Python**: `select.select()` for non-blocking I/O
- **Node.js**: Event-driven socket events (`data`, `error`, `close`, `timeout`)

### JSON Parsing
- **Python**: `json.loads()` with error handling
- **Node.js**: `JSON.parse()` with try-catch and buffering for incomplete messages

### Authentication
- **Python**: SHA-256 hash comparison
- **Node.js**: Same SHA-256 implementation using `crypto` module

### File Operations
- **Python**: Direct file I/O with `open()` and `write()`
- **Node.js**: `fs.writeFileSync()` for synchronous file writing

## Security Features

- SHA-256 authentication token
- Connection timeouts
- Input validation
- Error handling and logging
- Secure file operations

## Requirements

- Node.js 14.0.0 or higher
- No external dependencies (uses built-in Node.js modules)

## Logging

The server logs all activities to both console and file:
- Connection events
- Authentication attempts
- Command execution
- Errors and warnings
- Screenshot saves

Log file: `server_enhanced.log` 