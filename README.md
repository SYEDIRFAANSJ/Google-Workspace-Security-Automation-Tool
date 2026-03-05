# 🛡️ GWS Security Dashboard

A comprehensive **Google Workspace Security Dashboard** designed for CISOs and security administrators to monitor, audit, and manage security configurations across their organization.

![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)
![Express](https://img.shields.io/badge/Express-4.x-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 📋 Table of Contents

- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [API Endpoints](#-api-endpoints)
- [Scheduled Scans](#-scheduled-scans)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)

---

## ✨ Features

- **User Security Audit** - Monitor all users' security posture including MFA enrollment, login activity, and password age
- **Email Security Checks** - Verify SPF, DKIM, and DMARC configurations for your domain
- **Third-Party App Monitoring** - Track OAuth applications with access to sensitive scopes (Drive, Gmail)
- **Alert Center Integration** - View phishing and suspicious login alerts from Google Alert Center
- **Gmail Settings Analysis** - Detect auto-forwarding, IMAP/POP access, and external forwarding rules
- **Mobile Device Tracking** - Monitor mobile device access across users
- **Admin Role Visibility** - Identify users with administrative privileges
- **BigQuery Integration** (Optional) - Enhanced password change tracking via BigQuery logs
- **Scheduled Scans** - Configure automated daily security scans
- **🤖 AI-Powered Security Assistant** - Integrated Groq AI chat for security insights, threat analysis, and recommendations
- **📊 AI Risk Scoring Engine** - Automated risk assessment and scoring for your workspace security posture
- **📋 AI Compliance Monitoring** - AI-driven compliance checks and policy recommendations

---

## 📦 Prerequisites

Before you begin, ensure you have the following:

1. **Node.js** (v18.0.0 or higher)
2. **Google Cloud Project** with the following APIs enabled:
   - Admin SDK API
   - Gmail API
   - Google Workspace Alert Center API
   - BigQuery API (optional)
3. **Service Account** with domain-wide delegation configured
4. **Super Admin Account** for impersonation
5. **Groq API Key** (free) - Get it from [console.groq.com](https://console.groq.com/) for AI features

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/SYEDIRFAANSJ/Google-Workspace-Security-Automation-Tool.git
cd Google-Workspace-Security-Automation-Tool
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment Variables

Create a `.env` file in the root directory:

```env
# Port for the application to run on
PORT=3000

# A long, random, and secret string used for session and encryption
# IMPORTANT: Generate a secure random string (minimum 32 characters)
APP_SECRET=your-very-long-and-random-secret-string-here-make-it-secure

# Groq AI API Key (required for AI features)
# Get your free API key at https://console.groq.com/
GROQ_API_KEY=your-groq-api-key-here
```

> ⚠️ **Security Warning**: Use a strong, unique `APP_SECRET`. This is used to encrypt sensitive credentials stored in `config.json`.

### 4. Start the Application

**Production:**
```bash
npm start
```

**Development (with auto-reload):**
```bash
npm run dev
```

The application will be available at `http://localhost:3000`

---

## ⚙️ Configuration

### First-Time Setup

1. Navigate to `http://localhost:3000/login`
2. Enter your Google Workspace configuration:

| Field | Description |
|-------|-------------|
| **Admin User Email** | Super Admin email for API impersonation |
| **Domain** | Your Google Workspace domain (e.g., `example.com`) |
| **Project ID** | Google Cloud project ID |
| **Private Key ID** | From your service account JSON |
| **Private Key** | The full private key from service account JSON |
| **Client Email** | Service account email address |
| **Client ID** | Service account client ID |

### Optional: BigQuery Integration

Enable BigQuery for enhanced password change tracking:

| Field | Description |
|-------|-------------|
| **Use BigQuery** | Toggle to enable |
| **BigQuery Project ID** | Project containing admin logs |
| **BigQuery Dataset Name** | Dataset name (typically starts with `cloudaudit_`) |

### Service Account Required Scopes

Your service account must have domain-wide delegation with these OAuth scopes:

```
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.device.mobile.readonly
https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly
https://www.googleapis.com/auth/admin.directory.user.security
https://www.googleapis.com/auth/admin.reports.audit.readonly
https://www.googleapis.com/auth/apps.alerts
https://www.googleapis.com/auth/gmail.settings.basic
```

---

## 🖥️ Usage

### Login

1. Open `http://localhost:3000/login`
2. Enter your service account credentials
3. Click **Submit** to validate and save configuration

### Dashboard

After successful login, you'll be redirected to the main dashboard where you can:

- **Run Manual Scan** - Trigger an immediate security audit
- **View Latest Results** - See cached data from previous scans
- **Configure Schedule** - Set up automated daily scans
- **View Settings** - Review current configuration

---

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/login` | GET | Display login/configuration page |
| `/login` | POST | Submit configuration and authenticate |
| `/logout` | GET | End session and logout |
| `/` | GET | Main dashboard (requires auth) |
| `/api/run` | GET | Execute full security scan |
| `/api/latest` | GET | Retrieve cached scan results |
| `/api/config/view` | GET | View current configuration (sanitized) |
| `/api/schedule` | GET | Get current schedule settings |
| `/api/schedule` | POST | Update schedule settings |

---

## ⏰ Scheduled Scans

Configure automated scans through the dashboard:

1. Navigate to **Settings** → **Schedule**
2. Enable scheduled scans
3. Set preferred time (uses Asia/Kolkata timezone)
4. Save configuration

Scans run daily at the configured time and cache results for dashboard viewing.

---

## 🔧 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| **"APP_SECRET is not defined"** | Ensure `.env` file exists with valid `APP_SECRET` (min 32 chars) |
| **"Credential test failed"** | Verify service account has domain-wide delegation enabled |
| **"Configuration not found"** | Complete the setup at `/login` page |
| **Decryption errors** | `APP_SECRET` may have changed; reconfigure via `/login` |
| **API quota errors** | Reduce scan frequency or request quota increase |

### Logs

The application uses **Pino** for logging. Set log level in `.env`:

```env
LOG_LEVEL=debug  # Options: trace, debug, info, warn, error, fatal
```

---

## 📁 Project Structure

```
gws-security-dashboard/
├── index.js           # Main application server
├── config.json        # Encrypted credentials (auto-generated)
├── package.json       # Dependencies and scripts
├── .env               # Environment variables
└── public/
    ├── index.html     # Main dashboard UI
    ├── login.html     # Configuration/login page
    └── images/        # Static assets
```

---

## 🔐 Security Considerations

- **Credentials are encrypted** using AES-256-CBC before storage
- **Session-based authentication** for dashboard access
- **Never commit** `.env` or `config.json` to version control
- **Use HTTPS** in production environments
- **Rotate APP_SECRET** periodically (requires reconfiguration)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📧 Support

For issues and feature requests, please open an issue on GitHub.

---

**Made with ❤️ for Google Workspace Security**
