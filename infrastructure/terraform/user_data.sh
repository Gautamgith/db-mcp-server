#!/bin/bash
# User data script for MCP Server EC2 instance

set -e

# Update system
yum update -y

# Install required packages
yum install -y git docker nginx certbot python3-certbot-nginx htop tmux

# Install Node.js 18
curl -fsSL https://rpm.nodesource.com/setup_18.x | bash -
yum install -y nodejs

# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install
rm -rf aws awscliv2.zip

# Start and enable Docker
systemctl start docker
systemctl enable docker
usermod -a -G docker ec2-user

# Start and enable Nginx
systemctl start nginx
systemctl enable nginx

# Create application directory
mkdir -p /opt/mcp-server
chown ec2-user:ec2-user /opt/mcp-server

# Create environment file
cat > /opt/mcp-server/.env << EOF
# HTTP Server Configuration
MCP_SERVER_PORT=3000
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PATH=/mcp

# OAuth Configuration (EntraID/Azure AD)
# Set to 'true' to enable OAuth authentication
OAUTH_ENABLED=${oauth_enabled}
OAUTH_ISSUER=${oauth_issuer}
OAUTH_AUDIENCE=${oauth_audience}
OAUTH_JWKS_URI=${oauth_jwks_uri}
OAUTH_TOKEN_ALGORITHM=RS256
OAUTH_CLOCK_TOLERANCE=60

# Multi-Database Configuration
DATABASE_CONFIGS='[{"id":"prod","name":"Production DB","host":"${db_host}","port":5432,"database":"${db_name}","user":"${db_iam_user}","useIAM":true,"awsRegion":"${aws_region}","enabled":true}]'
DEFAULT_DATABASE_ID=prod

# AWS Configuration
AWS_REGION=${aws_region}

# MCP Configuration
MCP_SERVER_NAME=postgresql-mcp
MCP_SERVER_VERSION=1.0.0

# Logging Configuration
LOG_LEVEL=info
LOG_FORMAT=json
NODE_ENV=production

# Connection Pool Configuration
DB_POOL_MAX=10
DB_POOL_MIN=2
DB_POOL_IDLE_TIMEOUT=30000
DB_POOL_CONNECTION_TIMEOUT=5000

# Query Configuration
DEFAULT_QUERY_LIMIT=100
MAX_QUERY_LIMIT=1000
QUERY_TIMEOUT=30000

# Security Configuration
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW_MS=60000
MAX_QUERY_SIZE=10000
MAX_QUERY_COMPLEXITY_SCORE=20
EOF

chown ec2-user:ec2-user /opt/mcp-server/.env

# Clone repository and set up deployment
su - ec2-user << 'EOF'
cd /opt/mcp-server

# Clone the repository
git clone ${github_repo} .

# Install dependencies
npm install

# Build the application
npm run build

# Create systemd service files
sudo tee /etc/systemd/system/mcp-server.service > /dev/null << 'SERVICE'
[Unit]
Description=PostgreSQL MCP Server with HTTP/SSE and OAuth Authentication
After=network.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/opt/mcp-server
Environment=NODE_ENV=production
EnvironmentFile=/opt/mcp-server/.env
ExecStart=/usr/bin/node /opt/mcp-server/dist/index.js
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SERVICE

# Note: MCP Server now runs on port 3000 as HTTP service with /mcp endpoint
# MCP Inspector can be run separately on a different port if needed for testing

# Create logging interface service
sudo tee /etc/systemd/system/mcp-logs.service > /dev/null << 'LOGS'
[Unit]
Description=MCP Server Logging Interface
After=network.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/opt/mcp-server
Environment=NODE_ENV=production
ExecStart=/usr/bin/node /opt/mcp-server/deployment/scripts/log-server.js
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
LOGS

EOF

# Configure nginx
cat > /etc/nginx/conf.d/mcp-server.conf << 'NGINX'
# MCP Server HTTP/SSE proxy
server {
    listen 80;
    server_name _;

    # MCP Server endpoint (HTTP/SSE)
    location /mcp {
        proxy_pass http://localhost:3000/mcp;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Authorization $http_authorization;
        proxy_cache_bypass $http_upgrade;
    }

    # Health check endpoints
    location ~ ^/health {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Logging interface
    location /logs/ {
        proxy_pass http://localhost:8080/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }

    location / {
        root /var/www/html;
        index index.html;
    }
}
NGINX

# Create simple landing page
cat > /var/www/html/index.html << 'HTML'
<!DOCTYPE html>
<html>
<head>
    <title>PostgreSQL MCP Server</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .service { background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 8px; }
        .status { display: inline-block; padding: 4px 12px; border-radius: 4px; color: white; }
        .running { background: #28a745; }
        .stopped { background: #dc3545; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>PostgreSQL MCP Server</h1>
        <p>Environment: <strong>${environment}</strong></p>

        <div class="service">
            <h3>🔌 MCP Server Endpoint</h3>
            <p>HTTP/SSE transport with OAuth 2.0 authentication</p>
            <p><strong>Endpoint:</strong> <code>http://localhost:3000/mcp</code></p>
            <p><strong>Health Check:</strong> <a href="/health" target="_blank">/health</a></p>
        </div>

        <div class="service">
            <h3>📊 Logging Interface</h3>
            <p>Real-time logs and system monitoring</p>
            <p><a href="/logs/" target="_blank">View Logs</a></p>
        </div>

        <div class="service">
            <h3>📖 MCP Tools</h3>
            <p>10 comprehensive tools for database operations</p>
            <ul>
                <li>Database introspection (list_tables, describe_table)</li>
                <li>Query execution (execute_query, structured_query)</li>
                <li>Security analysis (validate_query_syntax, analyze_query_complexity)</li>
                <li>System monitoring (connection_health, security_status, rate_limit_status)</li>
                <li>Multi-database support (list_databases)</li>
            </ul>
        </div>

        <div class="service">
            <h3>🔐 Security Features</h3>
            <ul>
                <li>OAuth 2.0 authentication (EntraID/Azure AD)</li>
                <li>IAM database authentication</li>
                <li>Multi-layer SQL injection prevention</li>
                <li>Query pattern allowlisting</li>
                <li>Rate limiting (100 req/min default)</li>
                <li>PII detection and masking</li>
                <li>Model theft protection</li>
                <li>Excessive agency controls</li>
            </ul>
        </div>
    </div>
</body>
</html>
HTML

# Reload systemd and start services
systemctl daemon-reload
systemctl enable mcp-server mcp-logs
systemctl start mcp-server mcp-logs

# Restart nginx
systemctl restart nginx

# Setup log rotation
cat > /etc/logrotate.d/mcp-server << 'LOGROTATE'
/var/log/mcp-server/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
}
LOGROTATE

# Create deployment script
cat > /opt/mcp-server/deploy.sh << 'DEPLOY'
#!/bin/bash
# Deployment script for updating MCP server

set -e

echo "Starting deployment..."

# Stop services
sudo systemctl stop mcp-server

# Backup current version
if [ -d "/opt/mcp-server-backup" ]; then
    sudo rm -rf /opt/mcp-server-backup
fi
sudo cp -r /opt/mcp-server /opt/mcp-server-backup

# Pull latest changes
cd /opt/mcp-server
git pull origin main

# Install dependencies and build
npm install
npm run build

# Start services
sudo systemctl start mcp-server

echo "Deployment completed successfully!"
echo "Services status:"
sudo systemctl status mcp-server --no-pager -l
DEPLOY

chmod +x /opt/mcp-server/deploy.sh
chown ec2-user:ec2-user /opt/mcp-server/deploy.sh

# Create CloudWatch agent configuration
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'CLOUDWATCH'
{
    "logs": {
        "logs_collected": {
            "files": {
                "collect_list": [
                    {
                        "file_path": "/var/log/messages",
                        "log_group_name": "/aws/ec2/mcp-server/${environment}",
                        "log_stream_name": "{instance_id}/system"
                    },
                    {
                        "file_path": "/var/log/mcp-server/application.log",
                        "log_group_name": "/aws/ec2/mcp-server/${environment}",
                        "log_stream_name": "{instance_id}/application"
                    }
                ]
            }
        }
    },
    "metrics": {
        "namespace": "MCP/Server",
        "metrics_collected": {
            "cpu": {
                "measurement": ["cpu_usage_idle", "cpu_usage_iowait", "cpu_usage_user", "cpu_usage_system"],
                "metrics_collection_interval": 60
            },
            "disk": {
                "measurement": ["used_percent"],
                "metrics_collection_interval": 60,
                "resources": ["*"]
            },
            "mem": {
                "measurement": ["mem_used_percent"],
                "metrics_collection_interval": 60
            }
        }
    }
}
CLOUDWATCH

echo "EC2 instance setup completed successfully!"
echo "Services starting... Please allow a few minutes for all services to be ready."