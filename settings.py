####################################################
#                                                  #
# DO NOT INCLUDE CLIENT SECRETS IN THIS FILE !!!!! #
#                                                  #
# Instead, copy the file config-template.py to     #
# config.py (which is not committed to the repo)   #
# and put client secrets there.                    #
#                                                  #
####################################################

import os

TESTING = os.environ.get('SERVER_SOFTWARE', '').startswith('Development')

APP_DOMAIN = 'change-me-in-config-py.appspot.com'
APP_NAME = 'CHANGE-ME-IN-CONFIG.PY'
SERVICE_DISPLAYNAME = APP_NAME + ' OAuth Handler'
DEFAULT_TOKEN_VERSION = 1

API_KEY = ''
WORKER_URLS = []
WORKER_OFFLOAD_RATIO = 0

WL_CLIENT_ID = 'XXXXXXXXXXXXXXXXXXXX'
WL_CLIENT_SECRET = 'XXXXXXXXXXXXXXXXXXXX'
MSGRAPH_CLIENT_ID = 'XXXXXXXXXXXXXXXXXXXX'
MSGRAPH_CLIENT_SECRET = 'XXXXXXXXXXXXXXXXXXXX'
GD_CLIENT_ID = 'XXXXXXXXXXXXXXXXXXXX'
GD_CLIENT_SECRET = 'XXXXXXXXXXXXXXXXXXXX'
HC_CLIENT_ID = 'XXXXXXXXXXXXXXXXXXXX'
HC_CLIENT_SECRET = 'XXXXXXXXXXXXXXXXXXXX'
AMZ_CLIENT_ID = 'XXXXXXXXXXXXXXXXXXXX'
AMZ_CLIENT_SECRET = 'XXXXXXXXXXXXXXXXXXXX'
BOX_CLIENT_ID = 'XXXXXXXXXXXXXXXXXXXX'
BOX_CLIENT_SECRET = 'XXXXXXXXXXXXXXXXXXXX'
DROPBOX_CLIENT_ID = 'XXXXXXXXXXXXXXXXXXXX'
DROPBOX_CLIENT_SECRET = 'XXXXXXXXXXXXXXXXXXXX'

RATE_LIMIT = 0

try:
    from config import WL_CLIENT_ID
    from config import WL_CLIENT_SECRET
except ImportError:
    pass

try:
    from config import MSGRAPH_CLIENT_ID
    from config import MSGRAPH_CLIENT_SECRET
except ImportError:
    pass

try:
    from config import GD_CLIENT_ID
    from config import GD_CLIENT_SECRET
except ImportError:
    pass

try:
    from config import HC_CLIENT_ID
    from config import HC_CLIENT_SECRET
except ImportError:
    pass

try:
    from config import AMZ_CLIENT_ID
    from config import AMZ_CLIENT_SECRET
except ImportError:
    pass

try:
    from config import BOX_CLIENT_ID
    from config import BOX_CLIENT_SECRET
except ImportError:
    pass

try:
    from config import DROPBOX_CLIENT_ID
    from config import DROPBOX_CLIENT_SECRET
except ImportError:
    pass

try:
    from config import APP_DOMAIN
except ImportError:
    pass

try:
    from config import APP_NAME
except ImportError:
    pass

try:
    from config import SERVICE_DISPLAYNAME
except ImportError:
    pass

try:
    from config import RATE_LIMIT
except ImportError:
    pass

try:
    from config import TESTING
except ImportError:
    pass

try:
    from config import API_KEY
except ImportError:
    pass

try:
    from config import WORKER_URLS
except ImportError:
    pass

try:
    from config import WORKER_OFFLOAD_RATIO
except ImportError:
    pass

try:
    from config import DEFAULT_TOKEN_VERSION
except ImportError:
    pass

OAUTH_CALLBACK_URI = 'https://' + APP_DOMAIN + '/logged-in'

try:
    from config import OAUTH_CALLBACK_URI
except ImportError:
    pass

WL_REDIRECT_URI = OAUTH_CALLBACK_URI
WL_AUTH_URL = 'https://login.live.com/oauth20_token.srf'
WL_LOGIN_URL = 'https://login.live.com/oauth20_authorize.srf'

MSGRAPH_REDIRECT_URI = OAUTH_CALLBACK_URI
MSGRAPH_AUTH_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
MSGRAPH_LOGIN_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'

GD_REDIRECT_URI = OAUTH_CALLBACK_URI
GD_AUTH_URL = 'https://www.googleapis.com/oauth2/v3/token'
GD_LOGIN_URL = 'https://accounts.google.com/o/oauth2/auth'

HC_REDIRECT_URI = OAUTH_CALLBACK_URI
HC_AUTH_URL = 'https://api.hubic.com/oauth/token/'
HC_LOGIN_URL = 'https://api.hubic.com/oauth/auth/'

AMZ_REDIRECT_URI = OAUTH_CALLBACK_URI
AMZ_AUTH_URL = 'https://api.amazon.com/auth/o2/token'
AMZ_LOGIN_URL = 'https://www.amazon.com/ap/oa'

BOX_REDIRECT_URI = OAUTH_CALLBACK_URI
BOX_AUTH_URL = 'https://api.box.com/oauth2/token'
BOX_LOGIN_URL = 'https://app.box.com/api/oauth2/authorize'

DROPBOX_REDIRECT_URI = OAUTH_CALLBACK_URI
DROPBOX_AUTH_URL = 'https://api.dropboxapi.com/1/oauth2/token'
DROPBOX_LOGIN_URL = 'https://www.dropbox.com/1/oauth2/authorize'

LOOKUP = {
    'wl': {
        'display': 'Windows Live',
        'client-id': WL_CLIENT_ID,
        'client-secret': WL_CLIENT_SECRET,
        'redirect-uri': WL_REDIRECT_URI,
        'auth-url': WL_AUTH_URL,
        'login-url': WL_LOGIN_URL
    },

    'msgraph': {
        'display': 'Microsoft Graph',
        'client-id': MSGRAPH_CLIENT_ID,
        'client-secret': MSGRAPH_CLIENT_SECRET,
        'redirect-uri': MSGRAPH_REDIRECT_URI,
        'auth-url': MSGRAPH_AUTH_URL,
        'login-url': MSGRAPH_LOGIN_URL
    },

    'gd': {
        'display': 'Google',
        'client-id': GD_CLIENT_ID,
        'client-secret': GD_CLIENT_SECRET,
        'redirect-uri': GD_REDIRECT_URI,
        'auth-url': GD_AUTH_URL,
        'login-url': GD_LOGIN_URL
    },

    'hc': {
        'display': 'HubiC',
        'client-id': HC_CLIENT_ID,
        'client-secret': HC_CLIENT_SECRET,
        'redirect-uri': HC_REDIRECT_URI,
        'auth-url': HC_AUTH_URL,
        'login-url': HC_LOGIN_URL
    },

    'amz': {
        'display': 'Amazon',
        'client-id': AMZ_CLIENT_ID,
        'client-secret': AMZ_CLIENT_SECRET,
        'redirect-uri': AMZ_REDIRECT_URI,
        'auth-url': AMZ_AUTH_URL,
        'login-url': AMZ_LOGIN_URL
    },

    'box': {
        'display': 'Box.com',
        'client-id': BOX_CLIENT_ID,
        'client-secret': BOX_CLIENT_SECRET,
        'redirect-uri': BOX_REDIRECT_URI,
        'auth-url': BOX_AUTH_URL,
        'login-url': BOX_LOGIN_URL
    },
    'dropbox': {
        'display': 'Dropbox',
        'client-id': DROPBOX_CLIENT_ID,
        'client-secret': DROPBOX_CLIENT_SECRET,
        'redirect-uri': DROPBOX_REDIRECT_URI,
        'auth-url': DROPBOX_AUTH_URL,
        'login-url': DROPBOX_LOGIN_URL,
        'no-state-for-token-request': True,
        'no-refresh-tokens': True
    }
}

SERVICES = [
    {
        'display': 'Google Drive (limited)',
        'type': 'gd',
        'id': 'googledrive',
        'scope': 'https://www.googleapis.com/auth/drive.file',
        'extraurl': 'access_type=offline&approval_prompt=force',
        'servicelink': 'https://drive.google.com',
        'deauthlink': 'https://security.google.com/settings/security/permissions',
        'brandimage': '/google-btn.png'
    },
    {
        'display': 'Google Drive (full access)',
        'type': 'gd',
        'id': 'googledocs',
        'scope': 'https://www.googleapis.com/auth/drive',
        'extraurl': 'access_type=offline&approval_prompt=force',
        'servicelink': 'https://drive.google.com',
        'deauthlink': 'https://security.google.com/settings/security/permissions',
        'brandimage': '/google-btn.png'
    },
    {
        'display': 'Google Cloud Storage',
        'type': 'gd',
        'id': 'gcs',
        'scope': 'https://www.googleapis.com/auth/devstorage.read_write',
        'extraurl': 'access_type=offline&approval_prompt=force',
        'servicelink': 'https://cloud.google.com/storage/',
        'deauthlink': 'https://security.google.com/settings/security/permissions',
        'brandimage': '/google-btn.png'
    },
    {
        'display': 'Microsoft OneDrive (Live Connect API)',
        'type': 'wl',
        'id': 'onedrive',
        'scope': 'wl.offline_access wl.skydrive_update wl.skydrive',
        'servicelink': 'https://onedrive.live.com',
        'notes': '<p style="font-size: small">By using the OAuth login service for OneDrive you agree to the <a href="https://www.microsoft.com/en-us/servicesagreement" target="_blank">Microsoft Service Agreement</a> and <a href="https://privacy.microsoft.com/en-us/privacystatement" target="_blank">Microsoft Online Privacy Statement</a></p>'
    },
    {
        'display': 'Microsoft OneDrive (Microsoft Graph API)',
        'type': 'msgraph',
        'id': 'onedrivev2',
        'scope': 'offline_access Files.ReadWrite',
        'servicelink': 'https://onedrive.live.com',
        'notes': '<p style="font-size: small">By using the OAuth login service for OneDrive you agree to the <a href="https://www.microsoft.com/en-us/servicesagreement" target="_blank">Microsoft Service Agreement</a> and <a href="https://privacy.microsoft.com/en-us/privacystatement" target="_blank">Microsoft Online Privacy Statement</a></p>'
    },
    {
        'display': 'Microsoft SharePoint (Microsoft Graph API)',
        'type': 'msgraph',
        'id': 'sharepoint',
        'scope': 'offline_access Files.ReadWrite.All',
        'servicelink': 'https://products.office.com/en-us/sharepoint',
        'notes': '<p style="font-size: small">By using the OAuth login service for OneDrive you agree to the <a href="https://www.microsoft.com/en-us/servicesagreement" target="_blank">Microsoft Service Agreement</a> and <a href="https://privacy.microsoft.com/en-us/privacystatement" target="_blank">Microsoft Online Privacy Statement</a></p>'
    },
    {
        'display': 'Microsoft Office 365 Groups (Microsoft Graph API)',
        'type': 'msgraph',
        'id': 'msgroup',
        'scope': 'offline_access Files.ReadWrite.All Group.Read.All',
        'servicelink': 'https://support.office.com/en-us/article/Learn-about-Office-365-groups-b565caa1-5c40-40ef-9915-60fdb2d97fa2',
        'notes': '<p style="font-size: small">By using the OAuth login service for OneDrive you agree to the <a href="https://www.microsoft.com/en-us/servicesagreement" target="_blank">Microsoft Service Agreement</a> and <a href="https://privacy.microsoft.com/en-us/privacystatement" target="_blank">Microsoft Online Privacy Statement</a></p>'
    },
    {
        'display': 'HubiC',
        'type': 'hc',
        'id': 'hubic',
        'scope': 'credentials.r',
        'servicelink': 'https://hubic.com'
    },
    {
        'display': 'Amazon Cloud Drive',
        'type': 'amz',
        'id': 'amzcd',
        'scope': 'clouddrive:read_other clouddrive:write',
        'servicelink': 'https://www.amazon.com/clouddrive/home'
    },
    {
        'display': 'Box.com',
        'type': 'box',
        'id': 'box.com',
        'scope': 'root_readwrite',
        'servicelink': 'https://www.box.com/pricing/personal/'
    },
    {
        'display': 'Box.com',
        'type': 'box',
        'id': 'box',
        'scope': 'root_readwrite',
        'servicelink': 'https://www.box.com/pricing/personal/',
        'hidden': True
    },    
    {
        'display': 'Dropbox',
        'type': 'dropbox',
        'id': 'dropbox',
        'scope': '',
        'servicelink': 'https://dropbox.com'
    }
]

try:
    from config import POST_CONFIG

    POST_CONFIG(LOOKUP, SERVICES)
except ImportError:
    pass
