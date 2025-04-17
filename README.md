![License](https://img.shields.io/github/license/t0tex/ms365-geoip-alert)
![Python](https://img.shields.io/badge/python-3.8+-blue)

# MS365 Teams GeoIP Alert

This script monitors Microsoft 365 sign-ins from users in a specific Entra ID group and sends an alert to Microsoft Teams if a login is detected **outside a defined country**. It uses the Microsoft Graph API and Defender XDR (Advanced Hunting) API to track activity, suppress repeat alerts, and provide adaptive card alerts in real time.

---

## 🧪 Example Alert (Microsoft Teams)

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

        git clone https://github.com/t0tex/ms365-geoip-alert.git

        cd ms365-geoip-alert
    
2. Install dependencies

        pip install -r requirements.txt

📡 Azure App Registration (Microsoft Entra)
1. Register an app in Azure AD

   Go to: Azure Portal

      Navigate to Azure Active Directory > App registrations

       Click New registration

       Name it GeoIP Alert Monitor (Your Choice TBH)

       Leave redirect URI empty, click Register

2. Create a client secret

    Go to Certificates & secrets > New client secret

       Save the secret value securely

3. Assign API permissions

Microsoft Graph → Application permissions:
    Group.Read.All
    User.Read.All

Microsoft Defender for Endpoint (Security) → Application permissions:
    AdvancedHunting.Read.All

Click Grant admin consent
4. Capture the following for your .env

        Directory (tenant) ID
        Application (client) ID
        Client secret
        Group ID (security group containing the monitored users)
        Teams webhook URL

⚙️ Environment Configuration

Use the provided .env.example as a starting point. Create your own .env or environment file:

        TENANT_ID=your-tenant-id
        CLIENT_ID=your-client-id
        CLIENT_SECRET=your-client-secret
        GROUP_ID=your-group-id
        TEAMS_WEBHOOK=https://your-teams-webhook-url
        ALLOWED_COUNTRY=US              # Use 2-letter ISO country code (e.g. US, DE, MX)
        LOCAL_TZ=America/New_York       #  time zone string (e.g. Europe/Berlin)
        LOG_DIR=./logs                  # Directory for logs (default is ./logs)

You can load these using dotenv, export them directly, or use a systemd EnvironmentFile.

🚀 Running the Script

You can run the script manually:

        python3 ms365_geo_alert.py

Or use systemd to schedule it every hour

        [Unit]
        Description=MS365 Geo Alert Monitor
        After=network.target

        [Service]
        ExecStart=/usr/bin/python3 /opt/ms365_geo_alert/ms365_geo_alert.py
        Restart=always
        RestartSec=1h
        User=your-user
        Group=your-group
        Environment=PATH=/usr/bin:/usr/local/bin
        WorkingDirectory=/opt/ms365_geo_alert/
        StandardOutput=journal
        StandardError=journal
        EnvironmentFile=/etc/ms365_geo_alert.env

[Install]
WantedBy=multi-user.target

Update EnvironmentFile= to match your actual .env path (e.g. /etc/ms365_geo_alert.env)


2. Update the environment file path

Edit the file to ensure EnvironmentFile= points to your actual path (e.g. /etc/.env)


📁 Output & Logging

 Logs are written to the path specified in `LOG_DIR` (default is `./logs`):

        - CSV log: geo_alert.csv  
        - Log file: geo_alert.log  
        - Error log: geo_alert.error.log  
        - Alert cache: geo_alert.alerts.json  
        - Timestamp tracker: geo_alert.last_ts  


⚠️ Alert Suppression: Users are only alerted once every 8 hours, even if multiple events occur.
📄 License

This project is licensed under the MIT License. See the LICENSE file for full text.
