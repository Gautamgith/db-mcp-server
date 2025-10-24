#!/bin/bash
# Installation script for MCP Server systemd service

set -e

echo "Installing PostgreSQL MCP Server as systemd service..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or with sudo"
  exit 1
fi

# Create mcp-server user if it doesn't exist
if ! id "mcp-server" &>/dev/null; then
  echo "Creating mcp-server user..."
  useradd --system --no-create-home --shell /bin/false mcp-server
fi

# Create directories
echo "Creating directories..."
mkdir -p /opt/mcp-server
mkdir -p /etc/mcp-server
mkdir -p /opt/mcp-server/logs

# Copy service file
echo "Installing systemd service..."
cp mcp-server.service /etc/systemd/system/

# Set permissions
echo "Setting permissions..."
chown -R mcp-server:mcp-server /opt/mcp-server
chmod 755 /opt/mcp-server
chmod 755 /opt/mcp-server/logs

# Create example config if it doesn't exist
if [ ! -f /etc/mcp-server/config.env ]; then
  echo "Creating example configuration..."
  cat > /etc/mcp-server/config.env <<EOF
# HTTP Server Configuration
MCP_SERVER_PORT=3000
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PATH=/mcp

# OAuth Configuration
OAUTH_ENABLED=false

# Database Configuration
# Add your database configuration here

# Logging
LOG_LEVEL=info
LOG_FORMAT=json
NODE_ENV=production
EOF
  chmod 600 /etc/mcp-server/config.env
  echo "⚠️  Please edit /etc/mcp-server/config.env with your configuration"
fi

# Reload systemd
echo "Reloading systemd..."
systemctl daemon-reload

# Enable service
echo "Enabling service..."
systemctl enable mcp-server.service

echo "✅ Installation complete!"
echo ""
echo "Next steps:"
echo "1. Copy your application to /opt/mcp-server/"
echo "2. Edit /etc/mcp-server/config.env with your configuration"
echo "3. Start the service: sudo systemctl start mcp-server"
echo "4. Check status: sudo systemctl status mcp-server"
echo "5. View logs: sudo journalctl -u mcp-server -f"
