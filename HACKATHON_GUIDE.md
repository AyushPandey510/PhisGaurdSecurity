# 🚀 PhisGuard - Complete Hackathon Project Guide

## 📋 Project Overview

**PhisGuard** is a comprehensive web security analysis system consisting of:
- **Flask Backend API** - RESTful security analysis service
- **Chrome Extension** - Real-time browser security analysis
- **Advanced Security Features** - URL analysis, SSL validation, breach detection

**Built for hackathons** with enterprise-grade features in minimal time!

---

## 🏗️ Architecture & Technology Stack

### **Backend (Flask/Python)**
```python
# Core Dependencies (requirements.txt)
Flask==2.3.3              # Web framework
requests==2.31.0          # HTTP client
python-dotenv==1.0.0      # Environment variables
Flask-CORS==4.0.0         # Cross-origin support
Flask-Limiter==3.5.0      # Rate limiting
bleach==6.0.0             # Input sanitization
email-validator==2.1.0    # Email validation
flask-talisman==1.1.0     # Security headers
python-json-logger==2.0.7 # Structured logging
validators==0.22.0        # URL validation
```

### **Frontend (Chrome Extension)**
```json
// Build Dependencies (package.json)
"concurrently": "^8.2.2"     # Run multiple processes
"http-server": "^14.1.1"     # File server
"bestzip": "^2.2.1"          # ZIP packaging
```

### **External APIs & Local Data**
- **Google Safe Browsing API** - Real-time threat detection
- **VirusTotal API** - Advanced malware and phishing analysis
- **Local Breach Database** - Password and email breach checking (2100+ entries)

---

## 📁 Complete Project Structure

```
phisguard-backend/
├── 📄 app.py                          # Main Flask application
├── 📄 dev.py                          # Development runner script
├── 📄 run-dev.sh                      # Shell development script
├── 📄 package.json                    # Node.js build configuration
├── 📄 requirements.txt                # Python dependencies
├── 📄 README.md                       # Project documentation
├── 📄 HACKATHON_GUIDE.md             # This guide!
├── 📁 chrome-extension/              # Chrome extension source
│   ├── 📄 manifest.json              # Extension configuration
│   ├── 📄 popup.html                 # Extension popup UI
│   ├── 📄 popup.js                   # Popup functionality
│   ├── 📄 popup.css                  # Popup styling
│   ├── 📄 background.js              # Service worker
│   ├── 📄 content.js                 # Content script
│   └── 📄 content.css                # Content script styling
├── 📁 services/                      # Security analysis services
│   ├── 📄 url_checker.py             # URL risk analysis
│   ├── 📄 ssl_checker.py             # SSL certificate validation
│   ├── 📄 link_expander.py           # URL expansion service
│   └── 📄 breach_checker.py          # Password breach checking
├── 📁 utils/                         # Utility modules
│   └── 📄 risk_scorer.py             # Risk assessment logic
├── 📁 dist/                          # Built extension (auto-generated)
└── 📄 .env                           # Environment configuration
```

---

## 🎯 Core Features Implemented

### **🔍 Security Analysis Engine**
- **URL Risk Analysis** - Heuristic + Google Safe Browsing
- **SSL Certificate Validation** - Expiry alerts, issuer validation
- **Link Expansion** - Redirect chain analysis with visual arrows
- **Password Breach Detection** - Local breach database with 2100+ entries
- **Comprehensive Risk Scoring** - 0-100 risk assessment

### **🌐 Chrome Extension Features**
- **Real-time Analysis** - Instant security assessment
- **Automatic Link Scanning** - Visual indicators on web pages
- **Offline Support** - Cached results when backend unavailable
- **Professional UI** - Color-coded risk levels, progress bars
- **Background Processing** - Retry logic and error handling

### **🛡️ Enterprise Security**
- **Rate Limiting** - Flask-Limiter protection
- **Input Validation** - Comprehensive sanitization
- **CORS Support** - Chrome extension integration
- **Security Headers** - Flask-Talisman implementation
- **Structured Logging** - JSON logging for monitoring

---

## 🚀 Quick Start (5 Minutes)

### **1. Environment Setup**
```bash
# Install Python dependencies
pip install -r requirements.txt --break-system-packages

# Install Node.js dependencies
npm install

# Configure API keys and data file in .env
GOOGLE_SAFE_BROWSING_API_KEY=your-api-key-here
VIRUSTOTAL_API_KEY=your-virustotal-api-key-here
BREACH_DATA_FILE=breaches.json
```

### **2. Run Everything**
```bash
# Single command to run backend + extension
npm run dev
```

### **3. Load Extension**
1. Open `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select `dist/` folder
5. PhisGuard extension appears!

---

## 📚 API Endpoints

### **Core Security Analysis**
```bash
# Health check
GET /health
→ {"status": "healthy", "service": "phisguard-backend"}

# URL risk analysis
POST /check-url
→ {"url": "...", "risk_score": 25, "recommendation": "caution"}

# SSL certificate check
POST /check-ssl
→ {"ssl_valid": true, "risk_score": 0, "details": {...}}

# Link expansion
POST /expand-link
→ {"final_url": "...", "redirect_chain": [...], "analysis": {...}}

# Breach check
POST /check-breach
→ {"password_breach_check": {"breached": true, "breach_count": 14267}}
```

### **Advanced Features**
```bash
# Comprehensive analysis
POST /comprehensive-check
→ Full security report combining all checks

# Extension health
GET /extension/health
→ CORS-enabled health check for Chrome extension
```

---

## 🎨 Chrome Extension Architecture

### **Manifest V3 Configuration**
```json
{
  "manifest_version": 3,
  "name": "PhisGuard",
  "permissions": [
    "activeTab", "storage", "scripting",
    "http://localhost:5000/*"
  ],
  "action": {
    "default_popup": "popup.html",
    "default_icon": "icon.png"
  },
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["content.js"],
    "css": ["content.css"]
  }]
}
```

### **Component Breakdown**
- **popup.html/css/js** - User interface and interaction
- **background.js** - API communication and caching
- **content.js/css** - Automatic page analysis
- **manifest.json** - Extension configuration

---

## 🔧 Development Workflow

### **Rapid Development Cycle**
```bash
# 1. Make changes to source files
edit chrome-extension/popup.js

# 2. Rebuild extension
npm run build:dev

# 3. Reload in Chrome (one click)
# chrome://extensions/ → refresh PhisGuard

# 4. Test changes instantly!
```

### **Available Commands**
```bash
npm run dev              # Full development (backend + extension)
npm run build:dev        # Build extension only
npm run dev:backend      # Backend only
npm run dev:extension    # Extension server only
npm run build            # Production build
npm run setup            # Install all dependencies
```

---

## 🛡️ Security Features

### **Input Validation & Sanitization**
```python
# Flask backend validation
def validate_url(url):
    url = sanitize_input(url.strip())
    if not validators.url(url):
        return None, "Invalid URL format"
    return url, None

def validate_password_strength(password):
    # Comprehensive password validation
    # Length, character variety, common patterns
```

### **Rate Limiting**
```python
# Flask-Limiter configuration
limiter = Limiter(app=app, default_limits=["200 per day", "50 per hour"])

@app.route('/check-url', methods=['POST'])
@limiter.limit("10 per minute")
def check_url_endpoint():
    # Rate-limited endpoint
```

### **CORS & Security Headers**
```python
# Flask-CORS for extension support
CORS(app, origins=["chrome-extension://*"])

# Flask-Talisman security headers
talisman = Talisman(app, content_security_policy={...})
```

---

## 📊 Risk Scoring System

### **URL Risk Analysis**
```python
# Heuristic checks
if re.search(r"--", url):
    risk += 15  # Suspicious hyphens
if url.endswith((".xyz", ".top")):
    risk += 20  # Suspicious TLD

# Google Safe Browsing integration
if google_api_response.get("matches"):
    risk += 50  # Confirmed threat
```

### **SSL Risk Analysis**
```python
# Certificate expiry
if days_until_expiry <= 7:
    risk += 30  # Critical expiry
elif days_until_expiry <= 30:
    risk += 10  # Upcoming expiry

# Issuer validation
if subject_name == issuer_name:
    risk += 50  # Self-signed certificate
```

### **Link Expansion Risk**
```python
# Redirect chain analysis
if len(redirect_chain) > 3:
    risk += 20  # Too many redirects

# Domain mismatch
if original_domain != final_domain:
    risk += 15  # Suspicious redirect
```

---

## 🎯 Hackathon Implementation Strategy

### **Phase 1: Core Backend (30 minutes)**
```bash
# AI Prompt: "Create a Flask API with basic URL analysis"
# Focus: Basic Flask setup, URL validation, simple risk scoring
```

### **Phase 2: Chrome Extension (45 minutes)**
```bash
# AI Prompt: "Create a Chrome extension popup that calls Flask API"
# Focus: Manifest V3, popup UI, API integration
```

### **Phase 3: Advanced Security (45 minutes)**
```bash
# AI Prompt: "Add Google Safe Browsing and SSL analysis to Flask backend"
# Focus: External API integration, certificate validation
```

### **Phase 4: Polish & Features (30 minutes)**
```bash
# AI Prompt: "Add offline support, error handling, and professional UI"
# Focus: Caching, visual improvements, production readiness
```

---

## 🤖 Complete AI Prompt Collection

### **1. Initial Flask Backend**
```
Create a Flask REST API for URL security analysis with:
- Basic URL validation and sanitization
- Simple risk scoring based on heuristics
- CORS support for Chrome extension
- Error handling and logging
- Rate limiting for API protection
```

### **2. Chrome Extension Foundation**
```
Create a Chrome Manifest V3 extension with:
- Popup interface for URL input
- Background service worker for API calls
- Content scripts for page analysis
- Professional UI with loading states
- Error handling and offline support
```

### **3. Google Safe Browsing Integration**
```
Integrate Google Safe Browsing API into Flask backend:
- Proper API key handling
- Threat type configuration (MALWARE, SOCIAL_ENGINEERING)
- Error handling for API failures
- Risk score integration
- Fallback to heuristic analysis
```

### **4. SSL Certificate Analysis**
```
Add comprehensive SSL certificate checking:
- Certificate expiry date validation
- Issuer validation (self-signed detection)
- Certificate authority verification
- Risk scoring for SSL issues
- Visual expiry warnings
```

### **5. Password Breach Detection**
```
Implement local breach database integration:
- Secure password checking using SHA-1 hashes
- Breach count reporting from local dataset
- Password strength analysis
- Email breach checking with domain conversion
- Comprehensive security reporting
```

### **6. Link Expansion & Redirect Analysis**
```
Create URL expansion service with:
- Redirect chain following
- Visual chain display with arrows
- Suspicious redirect detection
- Domain mismatch analysis
- Risk scoring for redirect patterns
```

### **7. Professional UI & UX**
```
Enhance Chrome extension with:
- Color-coded risk visualization
- Progress bars and loading states
- Detailed analysis reports
- Responsive design
- Professional styling and icons
```

### **8. Production Readiness**
```
Add enterprise features:
- Comprehensive error handling
- Structured logging
- Security headers
- Input validation and sanitization
- Offline functionality with caching
- Build system and deployment
```

### **9. Unified Development Environment**
```
Create development workflow with:
- Single command to run everything
- Automatic extension building
- Process management and monitoring
- Hot reloading support
- Cross-platform compatibility
```

---

## 🏆 Hackathon Winning Features

### **Technical Excellence**
- ✅ **Modern Architecture** - Flask + Chrome Extension
- ✅ **Security Best Practices** - Input validation, rate limiting
- ✅ **External API Integration** - Google Safe Browsing, VirusTotal
- ✅ **Local Data Processing** - Breach database with 2100+ entries
- ✅ **Error Handling** - Comprehensive exception management
- ✅ **Performance** - Caching, async processing

### **User Experience**
- ✅ **Professional UI** - Clean, responsive design
- ✅ **Real-time Feedback** - Loading states, progress indicators
- ✅ **Visual Risk Assessment** - Color-coded warnings
- ✅ **Offline Support** - Cached results
- ✅ **Intuitive Workflow** - Simple one-click analysis

### **Scalability & Production**
- ✅ **Modular Architecture** - Service-based design
- ✅ **Configuration Management** - Environment variables
- ✅ **Build System** - Automated packaging
- ✅ **Documentation** - Comprehensive guides
- ✅ **Security** - Enterprise-grade protections

---

## 🚀 Deployment & Production

### **Environment Configuration**
```bash
# Production .env
FLASK_DEBUG=False
SECRET_KEY=your-production-secret-key
GOOGLE_SAFE_BROWSING_API_KEY=your-real-api-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
BREACH_DATA_FILE=breaches.json
```

### **Production Build**
```bash
# Create production extension
npm run build

# Deploy Flask app
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### **Docker Deployment**
```dockerfile
FROM python:3.9-slim
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
```

---

## 🎯 Success Metrics

### **Technical Achievement**
- ✅ **Complete Full-Stack Application**
- ✅ **Chrome Extension + Backend Integration**
- ✅ **External API Integrations**
- ✅ **Security Best Practices**
- ✅ **Production-Ready Code**

### **Innovation & Features**
- ✅ **Advanced Security Analysis**
- ✅ **Real-time Threat Detection**
- ✅ **Professional UI/UX**
- ✅ **Offline Functionality**
- ✅ **Comprehensive Risk Scoring**

### **Hackathon Impact**
- ✅ **Rapid Development** (2-3 hours to complete)
- ✅ **Enterprise Features** in short timeframe
- ✅ **Scalable Architecture**
- ✅ **Production Deployment Ready**
- ✅ **Comprehensive Documentation**

---

## 📞 Support & Resources

### **Quick Commands Reference**
```bash
# Development
npm run dev              # Full development environment
npm run build:dev        # Build extension
npm run dev:backend      # Backend only

# Production
npm run build            # Production build
python app.py            # Run backend

# Testing
curl http://localhost:5000/health  # API health check
```

### **Common Issues & Solutions**
```bash
# Extension not loading
# → Check dist/ folder exists and reload in chrome://extensions/

# API connection failed
# → Ensure backend is running on port 5000

# Build errors
# → Run npm install to update dependencies

# Permission errors
# → Use --break-system-packages for pip on some systems
```

---

## 🏅 Hackathon Project Summary

**PhisGuard** demonstrates how to build a **complete, enterprise-grade security application** in a hackathon timeframe using modern web technologies and best practices.

### **Key Achievements:**
- **Full-Stack Application** with Flask backend and Chrome extension
- **Advanced Security Features** including Google Safe Browsing integration
- **Professional UI/UX** with real-time analysis and visual feedback
- **Production-Ready Architecture** with security, caching, and error handling
- **Comprehensive Documentation** for easy replication and deployment

### **Perfect for Hackathons:**
- **Rapid Development** - Complete in 2-3 hours
- **Impressive Features** - Enterprise-grade security analysis
- **Modern Tech Stack** - Flask, Chrome Extension, external APIs
- **Scalable Architecture** - Service-based design
- **Production Ready** - Deployable with minimal changes

**Ready to win hackathons with enterprise-level security features! 🏆**