# MS365 Teams GeoIP Alert

This script monitors Microsoft 365 sign-ins from users in a specific Entra ID group and sends an alert to Microsoft Teams if a login is detected **outside a defined country**. It uses the Microsoft Graph API and Defender XDR (Advanced Hunting) API to track activity, suppress repeat alerts, and provide adaptive card alerts in real time.

![GeoIP Alert Screenshot](https://github.com/t0tex/ms365-geoip-alert/blob/main/Geo%20IP%20Notificaiotn.png?raw=true)

---

## 🔐 Prerequisites

To use this script, your Microsoft 365 tenant must have the following:

- **Microsoft Entra ID P2** (formerly Azure AD Premium P2)  
- **Microsoft Defender for Endpoint Plan 2**

Also required:
- Admin privileges to register an Azure AD app and grant permissions
- A Microsoft Teams channel with an **Incoming Webhook**
- Python 3.8 or newer (Python 3.9+ preferred)

---

## 🛠 Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/t0tex/ms365-geoip-alert.git
cd ms365-geoip-alert
