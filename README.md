# SecureShield Pro

## 🛡️ Modern Security Platform

SecureShield Pro is a comprehensive cybersecurity platform that provides advanced SAST/DAST scanning, AI-powered threat analysis, and professional security management with a beautiful glassmorphism UI design.

![SecureShield Pro](https://img.shields.io/badge/SecureShield-Pro-blue?style=for-the-badge&logo=shield)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.12+-blue?style=for-the-badge&logo=python)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue?style=for-the-badge&logo=typescript)
![React](https://img.shields.io/badge/React-18+-blue?style=for-the-badge&logo=react)

## ✨ Features

### 🚀 Core Security Features
- **Advanced SAST Scanning** - Static analysis with Bandit, Semgrep, and custom rules
- **Dynamic DAST Testing** - Runtime vulnerability detection for web applications
- **Dependency Scanning** - Python package vulnerability detection with Safety
- **Secret Detection** - Automated detection of hardcoded secrets and credentials
- **AI-Powered Analysis** - Intelligent threat analysis with Ollama + OpenRouter integration

### 🔐 Authentication & Security
- **Multi-Factor Authentication** - TOTP-based 2FA with QR code setup
- **OAuth Integration** - Google and GitHub OAuth support
- **Email/OTP Verification** - Secure email-based authentication
- **JWT Tokens** - Secure access and refresh token management
- **Role-Based Access Control** - Admin, Analyst, and Viewer roles

### 🎨 Modern UI/UX
- **Glassmorphism Design** - Beautiful iOS-style transparent interface
- **Dark/Light Themes** - Automatic theme switching with system preference
- **Responsive Design** - Mobile-first design that works on all devices
- **Real-time Updates** - Live scan progress and results
- **Interactive Charts** - Beautiful data visualization with Recharts

### 🏗️ Enterprise Architecture
- **FastAPI Backend** - High-performance Python API with async support
- **Next.js Frontend** - Modern React framework with TypeScript
- **MySQL Database** - Reliable relational database with connection pooling
- **Docker Support** - Containerized deployment with Docker Compose
- **Microservices Ready** - Scalable architecture for enterprise deployment

## 🚀 Quick Start

### Prerequisites

- **Python 3.12+**
- **Node.js 18+**
- **MySQL 8.0+**
- **Docker & Docker Compose** (optional)

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/secureshield-pro.git
cd secureshield-pro
```

### 2. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Initialize database
python -m app.db.init_db

# Run backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Configure environment
cp .env.example .env.local
# Edit .env.local with your settings

# Run frontend
npm run dev
```

### 4. Database Setup

```sql
-- Create database
CREATE DATABASE secureshield_pro CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user
CREATE USER 'secureshield'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON secureshield_pro.* TO 'secureshield'@'localhost';
FLUSH PRIVILEGES;
```

### 5. Security Tools Installation

```bash
# Install SAST tools
pip install bandit semgrep safety

# Install Ollama (for local AI)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama2

# Configure OpenRouter (optional)
# Get API key from https://openrouter.ai/
```

## 🐳 Docker Deployment

### Quick Deploy with Docker Compose

```bash
# Clone and navigate
git clone https://github.com/your-org/secureshield-pro.git
cd secureshield-pro

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Access application
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

### Production Deployment

```bash
# Production build
docker-compose -f docker-compose.prod.yml up -d

# Scale services
docker-compose -f docker-compose.prod.yml up -d --scale backend=3

# Monitor services
docker-compose -f docker-compose.prod.yml ps
```

## ⚙️ Configuration

### Backend Environment Variables

```bash
# Application
APP_NAME="SecureShield Pro"
DEBUG=false
SECRET_KEY="your-super-secret-key-change-in-production"

# Database
DB_HOST=localhost
DB_PORT=3306
DB_USER=secureshield
DB_PASSWORD=your_secure_password
DB_NAME=secureshield_pro

# Authentication
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# OAuth
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# Email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
SMTP_TLS=true

# AI Services
OLLAMA_BASE_URL=http://localhost:11434
OPENROUTER_API_KEY=your_openrouter_api_key

# Security
SEMGREP_API_TOKEN=your_semgrep_token
ENABLE_BACKGROUND_SCANS=true
MAX_SCAN_FILE_SIZE_MB=100
```

### Frontend Environment Variables

```bash
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_APP_NAME="SecureShield Pro"
NEXT_PUBLIC_GOOGLE_CLIENT_ID=your_google_client_id
NEXT_PUBLIC_GITHUB_CLIENT_ID=your_github_client_id
```

## 📚 API Documentation

### Authentication Endpoints

```bash
# Register user
POST /api/v1/auth/register
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "full_name": "John Doe"
}

# Login
POST /api/v1/auth/login
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}

# Setup 2FA
POST /api/v1/auth/2fa/setup
Authorization: Bearer <token>

# Verify 2FA
POST /api/v1/auth/2fa/verify
{
  "code": "123456"
}
```

### Scanning Endpoints

```bash
# Create scan
POST /api/v1/scans
{
  "name": "My App Scan",
  "scan_type": "sast",
  "target_path": "/path/to/code",
  "project_id": "project-uuid"
}

# Get scan results
GET /api/v1/scans/{scan_id}

# List findings
GET /api/v1/scans/{scan_id}/findings
```

### Dashboard Endpoints

```bash
# Get dashboard data
GET /api/v1/dashboard

# Get vulnerability trends
GET /api/v1/analytics/vulnerability-trends

# Get scan statistics
GET /api/v1/analytics/scan-stats
```

## 🛠️ Development

### Project Structure

```
secureshield-pro/
├── backend/                 # FastAPI backend
│   ├── app/
│   │   ├── api/            # API routes
│   │   ├── core/           # Core functionality
│   │   ├── db/             # Database models
│   │   ├── models/         # Pydantic schemas
│   │   ├── services/       # Business logic
│   │   └── main.py         # Application entry
│   ├── tests/              # Backend tests
│   └── requirements.txt    # Python dependencies
├── frontend/               # Next.js frontend
│   ├── src/
│   │   ├── app/           # App router pages
│   │   ├── components/    # React components
│   │   ├── lib/           # Utility functions
│   │   └── types/         # TypeScript types
│   ├── public/            # Static assets
│   └── package.json       # Node dependencies
├── docs/                  # Documentation
├── docker-compose.yml     # Development setup
└── README.md             # This file
```

### Running Tests

```bash
# Backend tests
cd backend
pytest tests/ -v --cov=app

# Frontend tests
cd frontend
npm run test

# E2E tests
npm run test:e2e
```

### Code Quality

```bash
# Backend linting
cd backend
black app/ tests/
isort app/ tests/
flake8 app/ tests/
mypy app/

# Frontend linting
cd frontend
npm run lint
npm run type-check
```

## 🔧 Security Tools Integration

### SAST Scanners

- **Bandit** - Python-specific security linter
- **Semgrep** - Multi-language static analysis
- **Custom Rules** - Organization-specific security rules

### DAST Scanners

- **OWASP ZAP** - Web application security scanner
- **Custom Scripts** - Tailored dynamic testing

### Dependency Scanners

- **Safety** - Python package vulnerability database
- **npm audit** - Node.js dependency scanner
- **Snyk** - Commercial vulnerability database

## 🤖 AI Integration

### Local AI (Ollama)

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull models
ollama pull llama2
ollama pull codellama

# Start service
ollama serve
```

### Cloud AI (OpenRouter)

1. Sign up at [OpenRouter](https://openrouter.ai/)
2. Get API key from dashboard
3. Add to environment variables
4. Configure model preferences

## 🎨 UI Customization

### Glassmorphism Themes

The UI uses a custom glassmorphism design system:

```css
/* Glass components */
.glass {
  backdrop-filter: blur(16px);
  background: rgba(255, 255, 255, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.2);
}

/* Custom colors */
:root {
  --glass-primary: rgba(255, 255, 255, 0.1);
  --glass-secondary: rgba(255, 255, 255, 0.05);
  --primary-blue: #0ea5e9;
}
```

### Dark/Light Mode

Automatic theme switching based on system preference with manual override.

## 🚀 Performance Optimization

### Backend Optimizations

- **Async Processing** - Non-blocking scan execution
- **Connection Pooling** - Efficient database connections
- **Caching** - Redis for session and scan results
- **Rate Limiting** - API protection and performance

### Frontend Optimizations

- **Code Splitting** - Dynamic imports for large components
- **Image Optimization** - Next.js automatic image optimization
- **Bundle Analysis** - Webpack bundle analyzer
- **PWA Support** - Progressive Web App capabilities

## 📊 Monitoring & Analytics

### Application Monitoring

- **Health Checks** - Endpoint monitoring
- **Performance Metrics** - Response time tracking
- **Error Tracking** - Structured error logging
- **Resource Usage** - CPU, memory, disk monitoring

### Security Analytics

- **Vulnerability Trends** - Time-based vulnerability analysis
- **Risk Scoring** - CVSS-based risk assessment
- **Compliance Reporting** - Automated compliance reports
- **Threat Intelligence** - External threat feed integration

## 🔒 Security Best Practices

### Data Protection

- **Encryption at Rest** - Database encryption
- **Encryption in Transit** - TLS 1.3 everywhere
- **Key Management** - Secure key rotation
- **Data Anonymization** - PII protection

### Access Control

- **Principle of Least Privilege** - Minimal required permissions
- **Regular Access Reviews** - Periodic permission audits
- **Session Management** - Secure session handling
- **Audit Logging** - Comprehensive activity logging

## 📈 Scaling & Production

### Horizontal Scaling

```yaml
# Kubernetes deployment example
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secureshield-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secureshield-backend
  template:
    metadata:
      labels:
        app: secureshield-backend
    spec:
      containers:
      - name: backend
        image: secureshield/backend:latest
        ports:
        - containerPort: 8000
```

### Load Balancing

- **NGINX** - Reverse proxy and load balancer
- **HAProxy** - High availability proxy
- **Cloud Load Balancers** - AWS ALB, GCP Load Balancer

### Database Scaling

- **Read Replicas** - Separate read/write operations
- **Connection Pooling** - Efficient connection management
- **Query Optimization** - Performance tuning
- **Caching Strategy** - Redis for frequent queries

## 🆘 Troubleshooting

### Common Issues

#### Database Connection Issues

```bash
# Check MySQL status
systemctl status mysql

# Test connection
mysql -h localhost -u secureshield -p secureshield_pro

# Check logs
tail -f /var/log/mysql/error.log
```

#### Scan Tool Issues

```bash
# Check tool installation
which bandit semgrep safety

# Verify permissions
ls -la /usr/local/bin/bandit

# Test tools directly
bandit --version
semgrep --version
safety --version
```

#### Frontend Build Issues

```bash
# Clear cache
npm run clean
rm -rf .next node_modules
npm install

# Check Node version
node --version  # Should be 18+

# Build debugging
npm run build -- --debug
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Standards

- **Python**: Black formatting, type hints, docstrings
- **TypeScript**: ESLint rules, Prettier formatting
- **Commits**: Conventional commit messages
- **Tests**: Minimum 80% code coverage

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OWASP** - Security guidelines and best practices
- **FastAPI** - High-performance web framework
- **Next.js** - React framework for production
- **Tailwind CSS** - Utility-first CSS framework
- **Security Community** - Open source security tools

## 📞 Support

- **Documentation**: [docs.secureshield.pro](https://docs.secureshield.pro)
- **Issues**: [GitHub Issues](https://github.com/your-org/secureshield-pro/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/secureshield-pro/discussions)
- **Email**: support@secureshield.pro

---

**Made with ❤️ by the SecureShield Pro Team**

*Securing the digital world, one scan at a time.*