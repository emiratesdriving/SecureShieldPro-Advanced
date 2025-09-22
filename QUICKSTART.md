# SecureShield Pro - Quick Start Guide

## 🚀 Access Credentials

### Default Admin Account
- **Email**: `admin@secureshield.com`
- **Password**: `SecureAdmin123!`

## 🌐 Application URLs

- **Frontend**: http://localhost:3001 (redirected from 3000)
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/api/docs

## 🔧 Getting Started

1. **Start Backend Server**:
   ```bash
   cd backend
   python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

2. **Start Frontend Server**:
   ```bash
   cd frontend
   npm run dev
   ```

3. **Access Application**:
   - Navigate to http://localhost:3001
   - Use the admin credentials above to log in

## 🔐 Authentication Flow

1. **Login Page**: Shows OAuth options (Google, GitHub) and email/password login
2. **Protected Routes**: Automatically redirects unauthenticated users to login
3. **Dashboard Access**: Full functionality available after authentication
4. **Logout**: Clears tokens and redirects to login page

## 🛡️ Security Features

- JWT token-based authentication
- Route protection middleware
- CORS security headers
- Rate limiting on sensitive endpoints
- Password strength validation
- Secure token storage in localStorage

## 📱 Current Features

- ✅ **Dashboard**: Security metrics, recent activity, quick actions
- ✅ **Security Findings**: Vulnerability management with filtering
- ✅ **Compliance Reports**: Framework compliance tracking
- ✅ **Settings**: User account management and system configuration
- ✅ **AI Chat**: Secure AI-powered security analysis
- ✅ **Authentication**: Complete login/logout flow with route protection

## 🚧 Development Status

- **OAuth Integration**: In progress (Google/GitHub buttons added)
- **File Upload & Scanning**: Planned
- **Advanced Analytics**: Planned
- **Real-time Notifications**: Planned

## 🔍 API Endpoints

- `POST /api/v1/auth/auth/register` - User registration
- `POST /api/v1/auth/auth/login` - User login
- `GET /api/v1/auth/auth/me` - Get current user
- `POST /api/v1/ai/chat/message` - AI chat interaction
