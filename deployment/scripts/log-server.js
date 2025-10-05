#!/usr/bin/env node

/**
 * Real-time logging interface for PostgreSQL MCP Server
 * Provides web-based log viewing with filtering and search capabilities
 */

const express = require('express');
const { createServer } = require('http');
const { Server: SocketIOServer } = require('socket.io');
const { spawn } = require('child_process');
const { readFileSync, existsSync, watchFile } = require('fs');
const { join, dirname } = require('path');
const { fileURLToPath } = require('url');

// For compatibility with CommonJS
const __filename = __filename || '';
const __dirname = __dirname || process.cwd();

// Remove these lines as they're replaced above

const app = express();
const server = createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.LOG_SERVER_PORT || 8080;
const LOG_DIRS = [
  '/var/log',
  '/opt/mcp-server/logs',
  '/tmp'
];

// Store active log watchers
const logWatchers = new Map();
const connectedClients = new Set();

// Serve static files
app.use(express.static(join(__dirname, '../web')));

// API endpoints
app.get('/api/logs/list', (req, res) => {
  const logs = [];

  // System logs
  logs.push({
    name: 'MCP Server Application',
    path: 'journalctl-mcp-server',
    type: 'systemd',
    description: 'Main MCP server application logs'
  });

  logs.push({
    name: 'MCP Inspector',
    path: 'journalctl-mcp-inspector',
    type: 'systemd',
    description: 'MCP Inspector web interface logs'
  });

  logs.push({
    name: 'System Messages',
    path: '/var/log/messages',
    type: 'file',
    description: 'System-wide log messages'
  });

  logs.push({
    name: 'Nginx Access',
    path: '/var/log/nginx/access.log',
    type: 'file',
    description: 'Nginx web server access logs'
  });

  logs.push({
    name: 'Nginx Error',
    path: '/var/log/nginx/error.log',
    type: 'file',
    description: 'Nginx web server error logs'
  });

  // Application logs
  const appLogPath = '/opt/mcp-server/logs/application.log';
  if (existsSync(appLogPath)) {
    logs.push({
      name: 'MCP Application Log',
      path: appLogPath,
      type: 'file',
      description: 'Detailed MCP server application logs'
    });
  }

  res.json({ logs });
});

app.get('/api/logs/read/:logId', (req, res) => {
  const { logId } = req.params;
  const lines = parseInt(req.query.lines) || 100;

  try {
    let content = '';

    if (logId.startsWith('journalctl-')) {
      const service = logId.replace('journalctl-', '');
      const result = spawn('journalctl', ['-u', service, '-n', lines.toString(), '--no-pager'], {
        encoding: 'utf8'
      });

      result.stdout.on('data', (data) => {
        content += data;
      });

      result.on('close', (code) => {
        res.json({
          content: content,
          lines: content.split('\n').length,
          path: logId
        });
      });
    } else {
      if (existsSync(logId)) {
        const result = spawn('tail', ['-n', lines.toString(), logId], {
          encoding: 'utf8'
        });

        result.stdout.on('data', (data) => {
          content += data;
        });

        result.on('close', (code) => {
          res.json({
            content: content,
            lines: content.split('\n').length,
            path: logId
          });
        });
      } else {
        res.status(404).json({ error: 'Log file not found' });
      }
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/system/status', (req, res) => {
  const services = ['mcp-server', 'mcp-inspector', 'nginx'];
  const status = {};

  let completed = 0;

  services.forEach(service => {
    const result = spawn('systemctl', ['is-active', service], {
      encoding: 'utf8'
    });

    let output = '';
    result.stdout.on('data', (data) => {
      output += data.trim();
    });

    result.on('close', (code) => {
      status[service] = {
        active: output === 'active',
        status: output
      };

      completed++;
      if (completed === services.length) {
        res.json({ services: status, timestamp: new Date().toISOString() });
      }
    });
  });
});

// WebSocket connection handling
io.on('connection', (socket) => {
  console.log(`Client connected: ${socket.id}`);
  connectedClients.add(socket);

  socket.on('subscribe-log', (logPath) => {
    console.log(`Client ${socket.id} subscribing to log: ${logPath}`);

    if (!logWatchers.has(logPath)) {
      startLogWatcher(logPath);
    }

    socket.join(logPath);
  });

  socket.on('unsubscribe-log', (logPath) => {
    console.log(`Client ${socket.id} unsubscribing from log: ${logPath}`);
    socket.leave(logPath);

    // If no clients are watching this log, stop the watcher
    const room = io.sockets.adapter.rooms.get(logPath);
    if (!room || room.size === 0) {
      stopLogWatcher(logPath);
    }
  });

  socket.on('disconnect', () => {
    console.log(`Client disconnected: ${socket.id}`);
    connectedClients.delete(socket);
  });
});

function startLogWatcher(logPath) {
  if (logWatchers.has(logPath)) {
    return;
  }

  console.log(`Starting log watcher for: ${logPath}`);

  if (logPath.startsWith('journalctl-')) {
    const service = logPath.replace('journalctl-', '');
    const watcher = spawn('journalctl', ['-u', service, '-f', '--no-pager'], {
      encoding: 'utf8'
    });

    watcher.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter(line => line.trim());
      lines.forEach(line => {
        io.to(logPath).emit('log-line', {
          timestamp: new Date().toISOString(),
          content: line,
          source: logPath
        });
      });
    });

    watcher.on('error', (error) => {
      console.error(`Error watching ${logPath}:`, error);
    });

    logWatchers.set(logPath, watcher);
  } else if (existsSync(logPath)) {
    const watcher = spawn('tail', ['-f', logPath], {
      encoding: 'utf8'
    });

    watcher.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter(line => line.trim());
      lines.forEach(line => {
        io.to(logPath).emit('log-line', {
          timestamp: new Date().toISOString(),
          content: line,
          source: logPath
        });
      });
    });

    watcher.on('error', (error) => {
      console.error(`Error watching ${logPath}:`, error);
    });

    logWatchers.set(logPath, watcher);
  }
}

function stopLogWatcher(logPath) {
  const watcher = logWatchers.get(logPath);
  if (watcher) {
    console.log(`Stopping log watcher for: ${logPath}`);
    watcher.kill();
    logWatchers.delete(logPath);
  }
}

// Cleanup on exit
process.on('SIGINT', () => {
  console.log('Shutting down log server...');

  for (const [logPath, watcher] of logWatchers) {
    watcher.kill();
  }

  process.exit(0);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Log server running on port ${PORT}`);
  console.log(`WebSocket server ready for real-time log streaming`);
  console.log(`Connected clients: ${connectedClients.size}`);
});