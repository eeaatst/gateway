"""
Sıfır harici bağımlılık ile çalışan OIDC/UMA Gateway.
Sadece Python Standart Kütüphanesi kullanır.
NGINX Unit üzerinde çalışmak üzere tasarlanmıştır.

Uyarı: Oturumlar (session) bellekte tutulur ve kalıcı değildir.
Container yeniden başladığında tüm oturumlar sıfırlanır.
"""
import os
import json
import uuid
from http.cookies import SimpleCookie
from urllib.parse import urlencode, parse_qsl, urlparse, urlunparse
from urllib.request import urlopen, Request
from urllib.error import HTTPError

# --- Konfigürasyon ---
KC_URL = os.environ.get("KEYCLOAK_URL")
KC_REALM = os.environ.get("KEYCLOAK_REALM")
CLIENT_ID = os.environ.get("OIDC_CLIENT_ID")
CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET")
CALLBACK_URL = os.environ.get("OIDC_CALLBACK_URL")
BACKEND_URL = os.environ.get("BACKEND_SERVICE_URL")

KC_AUTH_URL = f"{KC_URL}/realms/{KC_REALM}/protocol/openid-connect/auth"
KC_TOKEN_URL = f"{KC_URL}/realms/{KC_REALM}/protocol/openid-connect/token"

# --- Bellek İçi Oturum Deposu ---
SESSIONS = {}

# --- Yardımcı Fonksiyonlar ---

def make_request(url, data=None, headers={}):
    """urllib kullanarak HTTP isteği yapan yardımcı fonksiyon."""
    req = Request(url, data=data, headers=headers)
    try:
        with urlopen(req) as response:
            return response.read(), response.status, response.getheaders()
    except HTTPError as e:
        return e.read(), e.code, e.headers.items()

def exchange_code_for_token(code):
    """Authorization code'u access token ile takas eder."""
    payload = urlencode({
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code': code,
        'redirect_uri': CALLBACK_URL
    }).encode('utf-8')
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    body, status, _ = make_request(KC_TOKEN_URL, data=payload, headers=headers)
    if status == 200:
        return json.loads(body)
    return None

def check_uma_permission(access_token, resource_path):
    """UMA iznini kontrol eder."""
    payload = urlencode({
        'grant_type': 'urn:ietf:params:oauth:grant-type:uma-ticket',
        'audience': CLIENT_ID,
        'permission': resource_path,
        'response_mode': 'decision'
    }).encode('utf-8')
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    body, status, _ = make_request(KC_TOKEN_URL, data=payload, headers=headers)
    if status == 200:
        return json.loads(body).get('result', False)
    return False

def proxy_request(environ, start_response):
    """İsteği backend'e proxy'ler."""
    path = environ.get('PATH_INFO', '')
    query = environ.get('QUERY_STRING', '')
    method = environ.get('REQUEST_METHOD')

    backend_url_parts = list(urlparse(BACKEND_URL))
    backend_url_parts[2] = path
    backend_url_parts[4] = query
    full_backend_url = urlunparse(backend_url_parts)

    headers = {
        key.replace('HTTP_', '', 1).replace('_', '-').title(): value
        for key, value in environ.items() if key.startswith('HTTP_')
    }
    headers['Host'] = urlparse(BACKEND_URL).netloc

    content_length = int(environ.get('CONTENT_LENGTH', 0))
    request_body = environ['wsgi.input'].read(content_length) if content_length > 0 else None
    
    body, status, resp_headers = make_request(
        full_backend_url, 
        data=request_body, 
        headers=headers
    )
    
    start_response(f"{status} Status", resp_headers)
    return [body]

# --- Ana WSGI Uygulaması ---

def application(environ, start_response):
    """Tüm istekleri karşılayan ana WSGI fonksiyonu."""
    path = environ.get('PATH_INFO', '')
    cookies = SimpleCookie(environ.get('HTTP_COOKIE', ''))
    session_id = cookies.get('session_id', None)
    
    user_session = SESSIONS.get(session_id.value) if session_id else None

    # 1. Callback Rotası
    if path == '/_callback':
        # DÜZELTİLMİŞ KISIM: 'environ' içindeki QUERY_STRING'i ayrıştırıyoruz.
        query_params = dict(parse_qsl(environ.get('QUERY_STRING', '')))
        state_from_query = query_params.get('state')
        code_from_query = query_params.get('code')

        if not user_session or state_from_query != user_session.get('state'):
            start_response('400 Bad Request', [('Content-Type', 'text/plain')])
            return [b'Invalid state parameter']

        if not code_from_query:
            start_response('400 Bad Request', [('Content-Type', 'text/plain')])
            return [b'Authorization code not found in callback']

        tokens = exchange_code_for_token(code_from_query)
        if not tokens:
            start_response('500 Internal Server Error', [('Content-Type', 'text/plain')])
            return [b'Failed to exchange code for token']
        
        user_session['access_token'] = tokens['access_token']
        redirect_to = user_session.pop('original_url', '/')
        
        start_response('302 Found', [('Location', redirect_to)])
        return []

    # 2. Login Rotası (veya oturumu olmayan herhangi bir istek)
    if not user_session or 'access_token' not in user_session:
        session_id = str(uuid.uuid4())
        state = str(uuid.uuid4())
        original_url = f"{environ.get('wsgi.url_scheme')}://{environ.get('HTTP_HOST')}{environ.get('PATH_INFO', '')}"
        if environ.get('QUERY_STRING'):
            original_url += f"?{environ.get('QUERY_STRING')}"
            
        SESSIONS[session_id] = {'state': state, 'original_url': original_url}
        
        auth_params = urlencode({
            'client_id': CLIENT_ID,
            'response_type': 'code',
            'scope': 'openid',
            'redirect_uri': CALLBACK_URL,
            'state': state
        })
        login_url = f"{KC_AUTH_URL}?{auth_params}"
        
        headers = [
            ('Location', login_url),
            ('Set-Cookie', f'session_id={session_id}; Path=/; HttpOnly')
        ]
        start_response('302 Found', headers)
        return []

    # 3. Oturumu olan ve yetkilendirilecek istekler
    if not check_uma_permission(user_session['access_token'], path):
        start_response('403 Forbidden', [('Content-Type', 'text/plain')])
        return [b'Access Denied by Policy Decision Point']

    # 4. Yetki varsa, backend'e proxy'le
    return proxy_request(environ, start_response)