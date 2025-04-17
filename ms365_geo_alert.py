import requests
from msal import ConfidentialClientApplication
import datetime
import json
import os
import traceback
import csv
import sys

try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except ImportError:
    from backports.zoneinfo import ZoneInfo  # for Python <3.9

# === Country Flag Emoji Helper ===
def country_code_to_flag(country_code):
    if not country_code or len(country_code) != 2:
        return ""
    return ''.join(chr(127397 + ord(c)) for c in country_code.upper())

# === Environment Variable Check ===
required_envs = ["TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "GROUP_ID", "TEAMS_WEBHOOK"]
for env_var in required_envs:
    if not os.environ.get(env_var):
        raise EnvironmentError(f"Missing environment variable: {env_var}")

# === Config ===
TENANT_ID = os.environ["TENANT_ID"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
GROUP_ID = os.environ["GROUP_ID"]
TEAMS_WEBHOOK = os.environ["TEAMS_WEBHOOK"]
ALLOWED_COUNTRY = os.environ.get("ALLOWED_COUNTRY", "US")
LOCAL_TZ = ZoneInfo(os.environ.get("LOCAL_TZ", "America/New_York"))
LOG_DIR = os.environ.get("LOG_DIR", "./logs")
os.makedirs(LOG_DIR, exist_ok=True)

GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH_API = "https://graph.microsoft.com/v1.0"
HUNTING_API = "https://graph.microsoft.com/beta/security/runHuntingQuery"

LOG_FILE = os.path.join(LOG_DIR, "geo_alert.log")
ERROR_LOG_FILE = os.path.join(LOG_DIR, "geo_alert.error.log")
LAST_TS_FILE = os.path.join(LOG_DIR, "geo_alert.last_ts")
ALERT_TRACK_FILE = os.path.join(LOG_DIR, "geo_alert.alerts.json")
CSV_FILE = os.path.join(LOG_DIR, "geo_alert.csv")

SUPPRESSION_HOURS = 8

def log_error(msg):
    timestamp = datetime.datetime.now(LOCAL_TZ).isoformat()
    with open(ERROR_LOG_FILE, "a", encoding="utf-8") as ef:
        ef.write(f"[{timestamp}] ERROR: {msg}\n")

try:
    now = datetime.datetime.now(LOCAL_TZ).isoformat()

    app = ConfidentialClientApplication(
        CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
        client_credential=CLIENT_SECRET
    )

    token_result = app.acquire_token_for_client(scopes=GRAPH_SCOPE)
    if "access_token" not in token_result:
        raise Exception("Graph token error: " + json.dumps(token_result, indent=2))
    headers = {"Authorization": f"Bearer {token_result['access_token']}"}

    # Get group members
    members = requests.get(f"{GRAPH_API}/groups/{GROUP_ID}/members", headers=headers, timeout=90).json()["value"]
    users = []
    for m in members:
        upn = m.get("userPrincipalName")
        if upn:
            users.append(upn)
        else:
            user_id = m.get("id")
            user_detail = requests.get(f"{GRAPH_API}/users/{user_id}", headers=headers, timeout=90).json()
            fallback_upn = user_detail.get("userPrincipalName")
            if fallback_upn:
                users.append(fallback_upn)
            else:
                log_error(f"Missing userPrincipalName for member ID: {user_id}")

    if not users:
        log_error("No valid users found in group.")
        exit(0)

    try:
        with open(LAST_TS_FILE) as f:
            last_seen = datetime.datetime.fromisoformat(f.read().strip())
            time_filter = f"| where Timestamp > datetime({last_seen.isoformat()})"
    except:
        time_filter = "| where Timestamp > ago(1d)"

    if os.path.exists(ALERT_TRACK_FILE):
        with open(ALERT_TRACK_FILE, "r") as f:
            alert_history = json.load(f)
    else:
        alert_history = {}

    user_array = json.dumps(users)
    kql = f'''
    let monitoredUsers = dynamic({user_array});
    AADSignInEventsBeta
    {time_filter}
    | where Country != "{ALLOWED_COUNTRY}"
    | where ErrorCode == 0
    | where ConditionalAccessStatus == 2
    | where AccountUpn in (monitoredUsers)
    | project Timestamp, AccountUpn, IPAddress, Country, City, State
    '''

    response = requests.post(
        HUNTING_API,
        headers={**headers, "Content-Type": "application/json"},
        json={"Query": kql},
        timeout=90
    )
    results = response.json().get("results", [])

    log_entries = []
    updated_alerts = False

    for r in results:
        user = r["AccountUpn"]
        timestamp = r["Timestamp"].split(".")[0]
        event_utc = datetime.datetime.fromisoformat(timestamp).replace(tzinfo=datetime.timezone.utc)
        event_local = event_utc.astimezone(LOCAL_TZ)

        last_alert = alert_history.get(user)
        if last_alert:
            last_alert_dt = datetime.datetime.fromisoformat(last_alert).replace(tzinfo=LOCAL_TZ)
            if (event_local - last_alert_dt) < datetime.timedelta(hours=SUPPRESSION_HOURS):
                continue

        country_code = r["Country"].upper()
        flag = country_code_to_flag(country_code)

        card = {
            "type": "AdaptiveCard",
            "version": "1.4",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "summary": "Outside-US login detected",
            "body": [
                {
                    "type": "TextBlock",
                    "text": "\ud83d\udea8 Outside-US login detected",
                    "weight": "Bolder",
                    "size": "Large",
                    "wrap": True
                },
                {
                    "type": "FactSet",
                    "facts": [
                        {"title": "User:", "value": user},
                        {"title": "IP:", "value": r["IPAddress"]},
                        {"title": "City:", "value": r["City"]},
                        {"title": "Country:", "value": flag},
                        {"title": "Time:", "value": event_local.strftime('%Y-%m-%d %H:%M:%S %Z')}
                    ]
                }
            ],
            "actions": [
                {
                    "type": "Action.OpenUrl",
                    "title": "View in Defender",
                    "url": "https://security.microsoft.com"
                }
            ]
        }

        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": card
                }
            ]
        }

        resp = requests.post(TEAMS_WEBHOOK, json=payload, timeout=90)
        if resp.status_code != 200:
            log_error(f"Webhook error {resp.status_code}: {resp.text}")

        log_entries.append(f"[{now}] ALERT: Outside-{ALLOWED_COUNTRY} login for {user} at {event_local}")

        with open(CSV_FILE, "a", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                event_local.strftime("%Y-%m-%d %H:%M:%S"),
                r["AccountUpn"],
                r["IPAddress"],
                r["City"],
                r["State"],
                r["Country"]
            ])

        alert_history[user] = event_local.isoformat()
        updated_alerts = True

    if log_entries:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            for entry in log_entries:
                f.write(entry + "\n")

    if updated_alerts:
        with open(ALERT_TRACK_FILE, "w") as f:
            json.dump(alert_history, f, indent=2)

    if results:
        newest = max(datetime.datetime.fromisoformat(r["Timestamp"].split(".")[0]) for r in results)
        with open(LAST_TS_FILE, "w") as f:
            f.write(newest.isoformat())

except Exception:
    log_error(traceback.format_exc())
