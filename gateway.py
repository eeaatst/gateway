import os
import json
import uuid
import requests
from urllib.parse import urlencode, parse_qsl
from mitmproxy import http, ctx

# --- Konfigürasyon (Ortam değişkenlerinden) ---
KC_BROWSER_URL = os.environ.get("KEYCLOAK_BROWSER_URL")
KC_INTERNAL_URL = os.environ.get("KEYCLOAK_URL")
KC_REALM = os.environ.get("KEYCLOAK_REALM")
CLIENT_ID = os.environ.get("OIDC_CLIENT_ID")
CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET")
CALLBACK_URL = os.environ.get("OIDC_CALLBACK_URL")

KC_AUTH_URL = f"{KC_BROWSER_URL}/realms/{KC_REALM}/protocol/openid-connect/auth"
KC_TOKEN_URL = f"{KC_INTERNAL_URL}/realms/{KC_REALM}/protocol/openid-connect/token"

# --- Sunucu tarafı oturum deposu ---
SESSIONS = {}

def check_uma_permission(access_token):
    """Keycloak UMA'dan izin kontrolü yapar."""
    payload = {'grant_type': 'urn:ietf:params:oauth:grant-type:uma-ticket', 'audience': CLIENT_ID, 'response_mode': 'decision'}
    headers = {'Authorization': f'Bearer {access_token}'}
    auth = (CLIENT_ID, CLIENT_SECRET)
    try:
        res = requests.post(KC_TOKEN_URL, data=payload, headers=headers, auth=auth)
        if res.status_code == 200 and res.json().get('result') is True:
            ctx.log.info("✅ UMA Check: Access GRANTED by Keycloak PDP")
            return True
        ctx.log.error(f"❌ UMA Check: Access DENIED by Keycloak PDP: {res.status_code} {res.text}")
        return False
    except requests.RequestException as e:
        ctx.log.error(f"❌ UMA Check: Keycloak connection error: {e}")
        return False

class OidcGateway:
    def request(self, flow: http.HTTPFlow) -> None:
        # ÖNCELİKLE OTURUM KONTROLÜ YAP
        session_id = flow.request.cookies.get("session_id", None)
        user_session = SESSIONS.get(session_id) if session_id else None

        # 1. Senaryo: Kullanıcının geçerli bir oturumu ve token'ı VAR
        if user_session and "access_token" in user_session:
            # Kullanıcı zaten login olmuş. Sadece UMA iznini kontrol et.
            # /login veya /_callback'e gitse bile, oturumu olduğu için işlem yapmasına izin ver.
            if not check_uma_permission(user_session["access_token"]):
                flow.response = http.Response.make(403, b'{"error": "Access Denied by Policy Decision Point"}', {"Content-Type": "application/json"})
            # İzin varsa, hiçbir şey yapma, istek backend'e gitsin.
            return

        # 2. Senaryo: Kullanıcının oturumu YOK ama CALLBACK adresine geliyor
        # Bu, login sürecinin bir parçasıdır.
        if flow.request.path.startswith("/_callback"):
            self.handle_callback(flow)
            return

        # 3. Senaryo: Kullanıcının oturumu YOK ve diğer tüm sayfalara gitmeye çalışıyor
        # (/get, /admin, /login dahil). Her durumda onu login olmaya zorla.
        self.handle_login(flow)
        return

    def handle_login(self, flow: http.HTTPFlow):
        # Yeni bir oturum başlat
        session_id = str(uuid.uuid4())
        state = str(uuid.uuid4())
        
        # Eğer kullanıcı doğrudan /login'e gelmediyse, geldiği adresi kaydet.
        # Eğer /login'e geldiyse, anasayfaya yönlendir.
        original_url = flow.request.pretty_url
        if "/login" in original_url:
            original_url = f"{flow.request.scheme}://{flow.request.host}/"

        SESSIONS[session_id] = {"state": state, "original_url": original_url}

        auth_params = urlencode({'client_id': CLIENT_ID, 'response_type': 'code', 'scope': 'openid', 'redirect_uri': CALLBACK_URL, 'state': state})
        login_url = f"{KC_AUTH_URL}?{auth_params}"
        
        # 302 Redirect yanıtı oluştur ve tarayıcıyı Keycloak'a yönlendir.
        flow.response = http.Response.make(
            302,
            b'',
            {"Location": login_url, "Set-Cookie": f"session_id={session_id}; Path=/; HttpOnly; SameSite=Lax"}
        )

    def handle_callback(self, flow: http.HTTPFlow):
        session_id = flow.request.cookies.get("session_id", None)
        user_session = SESSIONS.get(session_id) if session_id else None
        query_params = dict(parse_qsl(flow.request.url.split('?', 1)[1]))
        
        if not user_session or query_params.get("state") != user_session.get("state"):
            flow.response = http.Response.make(400, b"Invalid state parameter")
            return
            
        code = query_params.get("code")
        token_payload = {'grant_type': 'authorization_code', 'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET, 'code': code, 'redirect_uri': CALLBACK_URL}
        res = requests.post(KC_TOKEN_URL, data=token_payload)

        if res.status_code != 200:
            flow.response = http.Response.make(500, f"Failed to get token: {res.text}".encode())
            return

        tokens = res.json()
        user_session["access_token"] = tokens["access_token"]
        redirect_to = user_session.pop("original_url", "/")

        flow.response = http.Response.make(302, b'', {"Location": redirect_to})

addons = [OidcGateway()]