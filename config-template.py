# Copy this file to "config.py" and edit it

#TESTING = False

# Change this to the domain of the service
#APP_DOMAIN='change-me-in-config-py.appspot.com'

# Short name of the service
#APP_NAME = 'CHANGE-ME-IN-CONFIG.PY'

# Name to display on front page
#SERVICE_DISPLAYNAME = APP_NAME + ' OAuth Handler'

# Callback URI for OAuth
#OAUTH_CALLBACK_URI = 'https://' + APP_DOMAIN + '/logged-in'

# Sets a limit for how many requests can be performed in
# an hour for a single keyid+ip pair
#RATE_LIMIT = 4

# Conditional setup example:
#if TESTING:
#    OAUTH_CALLBACK_URI = 'http://localhost:12080/logged-in'

# If you need to modify the lookup table and service list,
# add this method
#def POST_CONFIG(lookup, services):
#    pass



######## OFFLOAD WORKERS AREA ##########

# These variables are for supporting external OAuth worker machines

# This key is required for requests to /export from the workers
# The key must be at least 10 characters long
#API_KEY=''

# Urls to the OAuth worker machines. Each url must end with /refresh.
# A cron job will check if the remote machines are responding by
# replacing the trailing /refresh with /isalive
#WORKER_URLS=[]

# The worker offload ratio controls how likely it is
# that a request is forwareded to a worker.
# 0.0 means "never" and 1.0 means always
#WORKER_OFFLOAD_RATIO=0


######## SECRETS AREA ##########

# Windows Live Secrets
# https://account.live.com/developers/applications/index
#WL_CLIENT_ID='XXXXXXXXXXXXXXXXXXXX'
#WL_CLIENT_SECRET='XXXXXXXXXXXXXXXXXXXX'

# Google Secrets
# https://console.developers.google.com
#GD_CLIENT_ID='XXXXXXXXXXXXXXXXXXXX'
#GD_CLIENT_SECRET='XXXXXXXXXXXXXXXXXXXX'

# HubiC secrets
# https://hubic.com/home/browser/apps/
#HC_CLIENT_ID='XXXXXXXXXXXXXXXXXXXX'
#HC_CLIENT_SECRET='XXXXXXXXXXXXXXXXXXXX'

# Amazon CloudDrive
#AMZ_CLIENT_ID='XXXXXXXXXXXXXXXXXXXX'
#AMZ_CLIENT_SECRET='XXXXXXXXXXXXXXXXXXXX'

# Box.com
#BOX_CLIENT_ID='XXXXXXXXXXXXXXXXXXXX'
#BOX_CLIENT_SECRET='XXXXXXXXXXXXXXXXXXXX'

# Dropbox
#DROPBOX_CLIENT_ID='XXXXXXXXXXXXXXXXXXXX'
#DROPBOX_CLIENT_SECRET='XXXXXXXXXXXXXXXXXXXX'

