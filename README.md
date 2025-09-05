# PhisGuard - Complete Security Analysis System

PhisGuard is a comprehensive security analysis system consisting of a Flask backend API and a Chrome extension for real-time phishing detection and security assessment.

## 🏗️ System Overview

- **Backend API**: RESTful Flask service providing security analysis endpoints
- **Chrome Extension**: Browser extension for real-time URL and security analysis
- **Integrated System**: Seamless communication between extension and backend for comprehensive security checks

## 🚀 Quick Start (Unified Development)

### **Option 1: One-Command Setup (Recommended)**
```bash
# Install all dependencies and setup everything
npm run setup

# Run both backend and extension with one command
npm run dev
```
**That's it!** Both servers will start automatically:
- 📡 Backend API: `http://localhost:5000`
- 📁 Extension files: `http://localhost:3000`

### **Option 2: Python Development Script**
```bash
python3 dev.py
```

### **Option 3: Shell Script**
```bash
./run-dev.sh
```

### **Option 4: Manual Setup**
```bash
# Install dependencies
pip install -r requirements.txt
npm install

# Build extension
npm run build:dev

# Start backend
python3 app.py

# In another terminal, serve extension files
npm run dev:extension
```

## 🔧 Loading the Extension

1. **Open Chrome** and go to: `chrome://extensions/`
2. **Enable "Developer mode"** (toggle in top right)
3. **Click "Load unpacked"**
4. **Select the `dist/` folder** from your project
5. **The PhisGuard extension** will appear with a shield icon

## 🎯 Using PhisGuard

- **Click the shield icon** in Chrome toolbar
- **Enter any URL** or use "Get Current Tab"
- **Choose analysis type**: URL Check, SSL Check, Link Expansion, Breach Check
- **View detailed security analysis** with risk scores and recommendations

## 🚀 Features

- **URL Risk Analysis**: Heuristic analysis, Google Safe Browsing integration, VirusTotal API, PhishTank checking
- **SSL Certificate Validation**: Certificate validity, expiration dates, issuer information
- **Link Expansion**: Follows URL redirects, detects URL shorteners with visual chain display
- **Password Breach Detection**: Local breach database with 2100+ entries (replaces HIBP API dependency)
- **Email Breach Detection**: Checks emails against local breach database with domain conversion
- **Comprehensive Risk Scoring**: Combines all security checks into overall risk assessment (0-100 scale)
- **RESTful API**: Clean, documented endpoints for easy integration
- **Chrome Extension**: Real-time browser security analysis with offline support
- **Environment Configuration**: Secure configuration management with .env files
- **Docker Support**: Complete containerization with health checks and volume mounts

## 🔌 Chrome Extension Usage

Once installed, the PhisGuard extension provides real-time security analysis:

### Basic Usage
1. **Click the extension icon** in your Chrome toolbar
2. **Enter a URL** or click "Get Current URL" to analyze the current page
3. **Choose analysis type**:
   - **URL Check**: Analyze URL for phishing risks
   - **SSL Check**: Validate SSL certificate
   - **Link Expansion**: Follow URL redirects
   - **Breach Check**: Check email/password against breach databases

### Features
- **Real-time Analysis**: Instant security assessment of any URL
- **Offline Support**: Cached results when backend is unavailable
- **Comprehensive Reports**: Detailed security analysis with risk scores
- **Visual Indicators**: Color-coded risk levels (Safe/Caution/Danger)
- **Background Processing**: Automatic analysis with retry logic

### Extension Permissions
The extension requires these permissions for full functionality:
- `activeTab`: Analyze current tab content
- `storage`: Cache analysis results
- `scripting`: Inject content scripts for analysis
- `http://localhost:5000/*`: Communicate with backend API

## 📋 Prerequisites

- Python 3.8+
- pip (Python package manager)

## 🛠️ Installation

1. **Clone the repository** (if applicable) or navigate to the project directory

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**:
    Copy the `.env.example` template and fill in your API keys:
    ```bash
    cp .env.example .env
    ```

    Edit `.env` and set your API keys:
    ```env
    GOOGLE_SAFE_BROWSING_API_KEY=your-google-safe-browsing-api-key
    VIRUSTOTAL_API_KEY=your-virustotal-api-key
    ```

    **⚠️ Security Note**: Never commit the `.env` file to version control!

## 🔧 Configuration

The application uses environment variables for configuration. Key settings in `.env`:

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_DEBUG` | Enable/disable debug mode | `True` |
| `SECRET_KEY` | Flask secret key | `your-super-secret-key-change-this-in-production` |
| `HOST` | Server host | `0.0.0.0` |
| `PORT` | Server port | `5000` |
| `REQUEST_TIMEOUT` | HTTP request timeout (seconds) | `10` |
| `MAX_REDIRECTS` | Maximum URL redirects to follow | `10` |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing API key | - |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | - |
| `BREACH_DATA_FILE` | Path to local breach data file | `breaches.json` |
| `API_KEY` | Backend API key for authentication | - |

## 🛠️ Development Setup

### Extension Development
1. **Install Node.js dependencies**:
   ```bash
   npm install
   ```

2. **Development build**:
   ```bash
   npm run package:dev  # Creates phisguard-extension-dev.zip
   ```

3. **Production build**:
   ```bash
   npm run build  # Creates phisguard-extension-v1.0.0.zip
   ```

4. **Version management**:
   ```bash
   npm run version:bump        # Patch version (1.0.0 -> 1.0.1)
   npm run version:bump:minor  # Minor version (1.0.0 -> 1.1.0)
   npm run version:bump:major  # Major version (1.0.0 -> 2.0.0)
   ```

### Backend Development
1. **Create virtual environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run in development mode**:
   ```bash
   python app.py
   ```

## 🚀 Running the Application

### Development Mode
```bash
python3 app.py
```

The application will start on `http://localhost:5000`

### Production Mode
Set `FLASK_DEBUG=False` in your `.env` file and consider using a WSGI server like Gunicorn:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Docker Deployment
For easy deployment and portability, use Docker:

1. **Build the Docker image**:
   ```bash
   docker build -t phisguard-backend .
   ```

2. **Run the container**:
   ```bash
   docker run -p 5000:5000 --env-file .env phisguard-backend
   ```

3. **Or use Docker Compose** (recommended):
   ```bash
   docker-compose up -d
   ```

### Cloud Deployment

#### Heroku
1. **Install Heroku CLI** and login:
   ```bash
   heroku login
   ```

2. **Create a new app**:
   ```bash
   heroku create your-phisguard-app
   ```

3. **Set environment variables**:
   ```bash
   heroku config:set FLASK_DEBUG=False
   heroku config:set SECRET_KEY=your-secret-key
   heroku config:set API_KEY=your-api-key
   # Add other required API keys
   ```

4. **Deploy**:
   ```bash
   git push heroku main
   ```

#### AWS EC2
1. **Launch an EC2 instance** with Ubuntu
2. **Connect via SSH** and install Docker:
   ```bash
   sudo apt update
   sudo apt install docker.io
   sudo systemctl start docker
   sudo systemctl enable docker
   ```

3. **Clone your repository** and run:
   ```bash
   docker-compose up -d
   ```

#### Google Cloud Run
1. **Build and push to GCR**:
   ```bash
   gcloud builds submit --tag gcr.io/PROJECT-ID/phisguard-backend
   ```

2. **Deploy to Cloud Run**:
   ```bash
   gcloud run deploy --image gcr.io/PROJECT-ID/phisguard-backend --platform managed
   ```

#### Railway
1. **Connect your GitHub repository** to Railway
2. **Set environment variables** in Railway dashboard
3. **Deploy automatically** on push

#### Render
1. **Connect your repository** to Render
2. **Choose "Web Service"** and select Docker
3. **Set environment variables** and deploy

## 📚 API Documentation

### Base URL
```
http://localhost:5000
```

### Endpoints

#### 0. Root Endpoint
- **GET** `/`
- **Description**: Get API information and available endpoints
- **Response**:
  ```json
  {
    "message": "PhisGuard Backend API",
    "version": "1.0.0",
    "endpoints": {
      "health": "/health",
      "check_url": "/check-url",
      "check_ssl": "/check-ssl",
      "expand_link": "/expand-link",
      "check_breach": "/check-breach",
      "comprehensive_check": "/comprehensive-check"
    }
  }
  ```

#### 1. Health Check
- **GET** `/health`
- **Description**: Check if the service is running
- **Response**:
  ```json
  {
    "status": "healthy",
    "service": "phisguard-backend"
  }
  ```

#### 2. Detailed Health Check
- **GET** `/health/detailed`
- **Description**: Comprehensive health check with system metrics
- **Response**:
  ```json
  {
    "status": "healthy",
    "service": "phisguard-backend",
    "system": {
      "cpu_percent": 15.2,
      "memory_percent": 45.8,
      "disk_usage": {"total": 1000000000, "used": 500000000, "free": 500000000}
    },
    "application": {
      "uptime_seconds": 3600,
      "active_connections": 5,
      "total_requests": 150
    }
  }
  ```

#### 3. Extension Health Check
- **GET** `/extension/health`
- **Description**: Health check optimized for Chrome extension
- **Response**:
  ```json
  {
    "status": "healthy",
    "service": "phisguard-backend",
    "extension_support": true,
    "cors_enabled": true,
    "supported_origins": ["chrome-extension://*"]
  }
  ```

#### 4. URL Risk Analysis
- **POST** `/check-url`
- **Description**: Analyze URL for phishing and security risks
- **Request Body**:
  ```json
  {
    "url": "https://example.com"
  }
  ```
- **Response**:
  ```json
  {
    "url": "https://example.com",
    "risk_score": 25,
    "details": ["Suspicious: too many hyphens"],
    "recommendation": "caution"
  }
  ```

#### 5. SSL Certificate Check
- **POST** `/check-ssl`
- **Description**: Validate SSL certificate for a domain
- **Request Body**:
  ```json
  {
    "url": "https://example.com"
  }
  ```
- **Response**:
  ```json
  {
    "url": "https://example.com",
    "ssl_valid": true,
    "details": {
      "subject": "CN=example.com",
      "issuer": "CN=Let's Encrypt",
      "not_before": "2023-01-01 00:00:00",
      "not_after": "2023-12-31 23:59:59",
      "is_expired": false
    }
  }
  ```

#### 6. Link Expansion
- **POST** `/expand-link`
- **Description**: Expand shortened URLs and follow redirects
- **Request Body**:
  ```json
  {
    "url": "https://bit.ly/example"
  }
  ```
- **Response**:
  ```json
  {
    "original_url": "https://bit.ly/example",
    "final_url": "https://example.com/real-page",
    "redirect_chain": [
      {
        "url": "https://bit.ly/example",
        "status_code": 301,
        "redirect_to": "https://example.com/real-page"
      }
    ],
    "redirect_count": 1
  }
  ```

#### 7. Breach Check
- **POST** `/check-breach`
- **Description**: Check if email/password has been compromised using local breach database
- **Request Body** (email only):
  ```json
  {
    "email": "user162@test.com"
  }
  ```
- **Request Body** (password only):
  ```json
  {
    "password": "butterfly"
  }
  ```
- **Request Body** (both):
  ```json
  {
    "email": "user162@test.com",
    "password": "butterfly"
  }
  ```
- **Response** (comprehensive check):
  ```json
  {
    "email_check": {
      "breached": true,
      "breach_count": 1,
      "breaches": ["Pwdb-Public"]
    },
    "password_breach_check": {
      "breached": true,
      "breach_count": 1
    },
    "password_strength_check": {
      "score": 35,
      "feedback": ["Include uppercase letters", "Include numbers", "Include special characters"]
    },
    "overall_risk": "high"
  }
  ```

#### 8. Comprehensive Security Check
- **POST** `/comprehensive-check`
- **Description**: Full security analysis combining all checks
- **Request Body**:
  ```json
  {
    "url": "https://example.com",
    "email": "user@example.com",
    "password": "mypassword123"
  }
  ```
- **Response**:
  ```json
  {
    "url": "https://example.com",
    "assessment": {
      "overall_score": 35.5,
      "risk_level": "medium",
      "components": {
        "url_risk": {"score": 20, "weight": 0.4, "details": [...]},
        "ssl_risk": {"score": 10, "weight": 0.2, "details": [...]},
        "redirect_risk": {"score": 15, "weight": 0.15, "details": [...]},
        "breach_risk": {"score": 50, "weight": 0.1, "details": [...]}
      },
      "recommendations": [
        "⚠️ MEDIUM RISK: Exercise caution when interacting with this resource.",
        "Verify the destination manually before proceeding."
      ]
    },
    "individual_checks": {
      "url_check": {...},
      "ssl_check": {...},
      "link_expansion": {...},
      "breach_check": {...}
    }
  }
  ```

## 🧪 Testing

Run the comprehensive test suite:

```bash
python3 test_app.py
```

This will test:
- Environment variable loading
- Module imports
- Basic functionality of all services

## 🔒 Security Considerations

### **API Keys & Secrets**
1. **Never commit** `.env` files to version control
2. **Use** `.env.example` as a template for required variables
3. **Rotate** API keys regularly in production
4. **Use** environment variables for production deployments

### **Security Best Practices**
1. **HTTPS**: Always use HTTPS in production
2. **Rate Limiting**: Implemented with Flask-Limiter
3. **Input Validation**: Comprehensive sanitization with bleach
4. **CORS**: Properly configured for Chrome extension
5. **Error Handling**: Sensitive details not exposed in production
6. **Logging**: Structured JSON logging for monitoring

### **Git Security**
- **`.gitignore`** includes all sensitive files
- **Environment templates** provided in `.env.example`
- **API keys** protected from accidental commits
- **Build artifacts** excluded from version control

## 📁 Project Structure

```
phisguard-backend/
├── 📄 app.py                          # Main Flask application
├── 📄 dev.py                          # Development runner script
├── 📄 run-dev.sh                      # Shell development script
├── 📄 package.json                    # Node.js build configuration
├── 📄 requirements.txt                # Python dependencies
├── 📄 README.md                       # Project documentation
├── 📄 HACKATHON_GUIDE.md             # Hackathon implementation guide
├── 📄 RELEASE_NOTES.md               # Release notes and changelog
├── 📄 .env                           # Environment configuration
├── 📄 .env.example                   # Environment template
├── 📄 breaches.json                  # Local breach database (2100+ entries)
├── 📄 test_app.py                    # Test suite
├── 📄 test_breach_debug.py           # Breach debugging utilities
├── 📄 update_breach_data.py          # Breach data management
├── 📄 docker-compose.yml             # Docker Compose configuration
├── 📄 Dockerfile                     # Docker container configuration
├── 📄 .dockerignore                  # Docker ignore patterns
├── 📄 .gitignore                     # Git ignore patterns
├── 📁 chrome-extension/              # Chrome extension source files
│   ├── 📄 manifest.json              # Extension manifest (Manifest V3)
│   ├── 📄 popup.html                 # Extension popup interface
│   ├── 📄 popup.js                   # Popup functionality
│   ├── 📄 popup.css                  # Popup styling
│   ├── 📄 background.js              # Service worker for API communication
│   ├── 📄 content.js                 # Content script for page analysis
│   ├── 📄 content.css                # Content script styling
│   └── 📄 icon.png                   # Extension icon
├── 📁 services/                      # Security analysis services
│   ├── 📄 url_checker.py             # URL risk analysis (Google Safe Browsing + VirusTotal)
│   ├── 📄 ssl_checker.py             # SSL certificate validation
│   ├── 📄 link_expander.py           # URL expansion and redirect analysis
│   └── 📄 breach_checker.py          # Local breach database checking
├── 📁 utils/                         # Utility modules
│   ├── 📄 risk_scorer.py             # Risk assessment logic
│   ├── 📄 config.py                  # Configuration management
│   ├── 📄 logger.py                  # Logging utilities
│   ├── 📄 health.py                  # Health check utilities
│   └── 📄 cache.py                   # Caching utilities
└── 📁 dist/                          # Built extension (auto-generated)
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📋 Release Notes

For detailed release information, see [RELEASE_NOTES.md](RELEASE_NOTES.md)

### Version 1.0.0 (Current)
- **Complete Security System**: Full-stack PhisGuard with Flask backend and Chrome extension
- **Advanced Security Features**:
  - Real-time URL risk analysis (Google Safe Browsing + VirusTotal)
  - SSL certificate validation with expiry alerts
  - Link expansion with visual redirect chain display
  - Local breach database (2100+ entries) replacing HIBP dependency
  - Email breach detection with domain conversion support
  - Comprehensive risk scoring (0-100 scale)
  - Chrome extension with offline caching and real-time analysis
  - RESTful API with full documentation and authentication
- **Technical Excellence**:
  - Flask backend with modular service architecture
  - Chrome Manifest V3 extension with professional UI
  - Docker containerization with health checks and volume mounts
  - Automated build system with npm scripts
  - Environment-based configuration management
  - Comprehensive error handling and structured logging
  - Rate limiting and security headers
  - Input validation and sanitization

### Future Releases
- **v1.1.0**: Enhanced UI, additional security checks, performance optimizations
- **v1.2.0**: Browser extension for Firefox, Safari
- **v2.0.0**: Machine learning-based threat detection, advanced analytics

## 📄 License

## 🔧 Troubleshooting

### Extension Issues
- **Extension not loading**: Ensure you're loading the `chrome-extension/` folder (not `dist/`) in developer mode
- **API connection failed**: Verify the backend is running on `http://localhost:5000`
- **Permission denied**: Check that the extension has the required permissions in `chrome://extensions/`
- **Cached results only**: Backend is offline; restart the Flask server

### Backend Issues
- **Import errors**: Run `pip install -r requirements.txt` to install all dependencies
- **Port already in use**: Change the PORT in `.env` or kill the process using port 5000
- **API key errors**: Ensure all required API keys are set in `.env` file
- **SSL certificate errors**: Some sites may block certificate inspection

### Build Issues
- **npm command not found**: Install Node.js from https://nodejs.org/
- **bestzip not found**: Run `npm install` to install dev dependencies
- **Permission errors**: Ensure you have write permissions in the project directory

### Common Solutions
1. **Clear browser cache** and reload the extension
2. **Restart Chrome** after loading/unloading extensions
3. **Check browser console** (F12) for JavaScript errors
4. **Verify API endpoints** are accessible: `curl http://localhost:5000/health`

## 🆘 Support

## 🔄 API Versioning

Current API version: v1.0.0

All endpoints are prefixed with `/` (root). Future versions may include version prefixes like `/v2/`.

---

**Built with ❤️ for cybersecurity and online safety**