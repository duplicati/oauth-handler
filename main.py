#!/usr/bin/env python

import base64
import datetime
import hashlib
import json
import logging
import google.cloud.logging
import random
import requests
import urllib.parse

import dbmodel
# TODO google.cloud.datastore is the new way to access datastore in App Engine. However, cloud ndb should still be supported, and is the replacement to app engine ndb.
from google.cloud import ndb
from google.appengine.api import wrap_wsgi_app, memcache
from flask import Flask, request, redirect, jsonify, render_template
import password_generator
import settings
import simplecrypt

app = Flask(__name__)
app.wsgi_app = wrap_wsgi_app(app.wsgi_app)
dbclient = ndb.Client()
logging.basicConfig(level=logging.INFO)
client = google.cloud.logging.Client()
client.setup_logging()

def ndb_wsgi_middleware(wsgi_app):
    def middleware(environ, start_response):
        with dbclient.context():
            return wsgi_app(environ, start_response)
    return middleware

app.wsgi_app = ndb_wsgi_middleware(app.wsgi_app)

def find_provider_and_service(id):
    providers = [n for n in settings.SERVICES if n['id'] == id]
    if len(providers) != 1:
        raise Exception(f'No such provider: {id}')

    provider = providers[0]
    return provider, settings.LOOKUP[provider['type']]


def find_service(id):
    id = id.lower()
    if id in settings.LOOKUP:
        return settings.LOOKUP[id]

    _, service = find_provider_and_service(id)
    return service


def create_authtoken(provider_id, token):
    # We store the ID if we get it back
    if 'user_id' in token:
        user_id = token["user_id"]
    else:
        user_id = "N/A"

    exp_secs = 1800  # 30 min guess
    try:
        exp_secs = int(token["expires_in"])
    except:
        pass

    # Create a random password and encrypt the response
    # This ensures that a hostile takeover will not get access
    #  to stored access and refresh tokens
    password = password_generator.generate_pass()
    cipher = simplecrypt.encrypt(password, json.dumps(token))

    # Convert to text and prepare for storage
    b64_cipher = base64.b64encode(cipher)
    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=exp_secs)

    entry = None
    keyid = None

    # Find a random un-used user ID, and store the encrypted data
    while entry is None:
        keyid = '%030x' % random.randrange(16 ** 32)
        entry = dbmodel.insert_new_authtoken(keyid, user_id, b64_cipher, expires, provider_id)

    # Return the keyid and authid
    return keyid, keyid + ':' + password


@app.route('/login', methods=['GET'])
def redirect_to_login():
    """Creates a state and redirects the user to the login page"""

    try:
        provider, service = find_provider_and_service(request.args.get('id', None))

        # Find a random un-used state token
        stateentry = None
        while stateentry is None:
            statetoken = '%030x' % random.randrange(16 ** 32)
            stateentry = dbmodel.insert_new_statetoken(statetoken, provider['id'], request.args.get('token', None),
                                                    request.args.get('tokenversion', None))

        link = service['login-url']
        link += '?client_id=' + service['client-id']
        link += '&response_type=code'
        link += '&scope=' + provider['scope']
        link += '&state=' + statetoken
        if 'extraurl' in provider:
            link += '&' + provider['extraurl']
        link += '&redirect_uri=' + service['redirect-uri']

        return redirect(link)

    except:
        logging.exception('handler error')
        response = jsonify({'error': 'Server error'})
        response.status_code = 500
        return response


@app.route('/', defaults={'path':''}, methods=['GET'])
@app.route('/<path:path>', methods=['GET'])
def index(path):
    """Renders the index.html file with contents from settings.py"""

    if path != '':
        logging.warning(f'Received unhandled path request: "{path}"')

    # If the request contains a token,
    #  register this with a limited lifetime
    #  so the caller can grab the authid automatically
    token = request.args.get('token', None)
    if token is not None:
        dbmodel.create_fetch_token(token)
        if settings.TESTING:
            logging.info('Created redir with token %s', token)

    filtertype = request.args.get('type', None)

    tokenversion = settings.DEFAULT_TOKEN_VERSION

    try:
        if request.args.get('tokenversion') is not None:
            tokenversion = int(request.args.get('tokenversion'))
    except:
        pass

    templateitems = []
    for n in settings.SERVICES:
        service = settings.LOOKUP[n['type']]

        # If there is a ?type= parameter, filter the results
        if filtertype is not None and filtertype != n['id']:
            continue

        # If the client id is invalid or missing, skip the entry
        if service['client-id'] is None or service['client-id'][0:8] == 'XXXXXXXX':
            continue

        if filtertype is None and 'hidden' in n and n['hidden']:
            continue

        link = ''
        if 'cli-token' in service and service['cli-token']:
            link = '/cli-token?id=' + n['id']
        else:
            link = '/login?id=' + n['id']
            if token is not None:
                link += '&token=' + token

            if tokenversion is not None:
                link += '&tokenversion=' + str(tokenversion)

        notes = ''
        if 'notes' in n:
            notes = n['notes']

        brandimg = ''
        if 'brandimage' in n:
            brandimg = n['brandimage']

        templateitems.append({
            'display': n['display'],
            'authlink': link,
            'id': n['id'],
            'notes': notes,
            'servicelink': n['servicelink'],
            'brandimage': brandimg
        })

    return render_template('index.html',
        redir=request.args.get('redirect', None),
        appname=settings.APP_NAME,
        longappname=settings.SERVICE_DISPLAYNAME,
        providers=templateitems,
        tokenversion=tokenversion)


@app.route('/logged-in', methods=['GET'])
def login():
    """
    Handles the login callback from the OAuth server
    This is called after the user grants access on the remote server
    After grabbing the refresh token, the logged-in.html page is
    rendered
    """

    display = 'Unknown'
    try:
        # Grab state and code from request
        state = request.args.get('state')
        code = request.args.get('code')

        if settings.TESTING:
            logging.info('Log-in with code %s, and state %s', code, state)

        if state is None or code is None:
            raise Exception('Response is missing state or code')

        statetoken = ndb.Key(dbmodel.StateToken, state).get()
        if statetoken is None:
            raise Exception('No such state found')

        if statetoken.expires < datetime.datetime.now(datetime.timezone.utc):
            raise Exception('State token has expired')

        provider, service = find_provider_and_service(statetoken.service)

        display = provider['display']

        redir_uri = service['redirect-uri']
        if request.args.get('token') is not None:
            redir_uri += request.args.get('token')

        if settings.TESTING:
            logging.info('Got log-in with url %s', redir_uri)
            logging.info('Sending to %s', service['auth-url'])

        # With the returned code, request a refresh and access token
        url = service['auth-url']

        request_params = {
            'client_id': service['client-id'],
            'redirect_uri': redir_uri,
            'client_secret': service['client-secret'],
            'state': state,
            'code': code,
            'grant_type': 'authorization_code'
        }

        # Some services do not allow the state to be passed
        if 'no-state-for-token-request' in service and service['no-state-for-token-request']:
            del request_params['state']

        data = urllib.parse.urlencode(request_params)

        if settings.TESTING:
            logging.info(f'REQ RAW: {data}')

        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        # Alternative method for sending auth, according to HubiC API
        # if service == 'hc':
        #     logging.info('Adding header ' + v['client-id'] + ':' + v['client-secret'])
        #     headers['Authorization'] = "Basic " + base64.b64encode(v['client-id'] + ':' + v['client-secret'])

        try:
            response = requests.post(url, data=data, headers=headers, timeout=20)
            response.raise_for_status()
            content = response.content
        except requests.HTTPError as err:
            logging.error(f'PROVIDER: {display}, {url}')
            logging.error(f'ERR-CODE: {err.response.status_code}')
            logging.error(f'ERR-BODY: {err.response.text}')
            if 'secret' in err.response.text.lower() or service['client-secret'] in err.response.text:
                raise err
            err_response = jsonify({'error': f'Request error: {err.response.text} (code: {err.response.status_code})'})
            err_response.headers['X-Reason'] = err.response.text
            err_response.status_code = 500
            return err_response

        if settings.TESTING:
            logging.info(f'RESP RAW: {content}')

        # OAuth response is JSON
        resp = json.loads(content)

        # If this is a service that does not use refresh tokens,
        # we just return the access token to the caller
        if 'no-refresh-tokens' in service and service['no-refresh-tokens']:
            dbmodel.update_fetch_token(statetoken.fetchtoken, resp['access_token'])

            # Report results to the user
            template_values = {
                'service': display,
                'appname': settings.APP_NAME,
                'longappname': settings.SERVICE_DISPLAYNAME,
                'authid': resp['access_token'],
                'fetchtoken': statetoken.fetchtoken
            }

            statetoken.key.delete()
            logging.info('Returned access token for service %s', provider['id'])

            return render_template('logged-in.html', **template_values)

        # This happens in some cases with Google's OAuth
        if 'refresh_token' not in resp:

            if 'deauthlink' in provider:
                template_values = {
                    'service': display,
                    'authid': f'Server error, you must de-authorize {settings.APP_NAME}',
                    'showdeauthlink': 'true',
                    'deauthlink': provider['deauthlink'],
                    'fetchtoken': ''
                }

                statetoken.key.delete()
                logging.info('No refresh token found for service %s', provider['id'])

                return render_template('logged-in.html', **template_values)

            else:
                raise Exception('No refresh token found, try to de-authorize the application with the provider')

        # v2 tokens are just the provider name and the refresh token
        # and they have no stored state on the server
        if statetoken.version == 2:
            authid = 'v2:' + statetoken.service + ':' + resp['refresh_token']
            dbmodel.update_fetch_token(statetoken.fetchtoken, authid)

            # Report results to the user
            template_values = {
                'service': display,
                'appname': settings.APP_NAME,
                'longappname': settings.SERVICE_DISPLAYNAME,
                'authid': authid,
                'fetchtoken': statetoken.fetchtoken
            }

            statetoken.key.delete()
            logging.info('Returned refresh token for service %s', provider['id'])

            return render_template('logged-in.html', **template_values)

        # Return the id and password to the user
        keyid, authid = create_authtoken(provider['id'], resp)

        fetchtoken = statetoken.fetchtoken

        # If this was part of a polling request, signal completion
        dbmodel.update_fetch_token(fetchtoken, authid)

        # Report results to the user
        template_values = {
            'service': display,
            'appname': settings.APP_NAME,
            'longappname': settings.SERVICE_DISPLAYNAME,
            'authid': authid,
            'fetchtoken': fetchtoken
        }

        statetoken.key.delete()
        logging.info('Created new authid %s for service %s', keyid, provider['id'])

        return render_template('logged-in.html', **template_values)

    except:
        logging.exception(f'handler error for {display}')
        error_code = request.args.get('error', None)
        error_desc = request.args.get('error_description', None)
        if error_code is not None:
            logging.error(f'Request error code: {error_code}')
        if error_desc is not None:
            logging.error(f'Request error description: {error_desc}')

        template_values = {
            'service': display,
            'appname': settings.APP_NAME,
            'longappname': settings.SERVICE_DISPLAYNAME,
            'authid': 'Server error, close window and try again',
            'fetchtoken': ''
        }

        return render_template('logged-in.html', **template_values)


@app.route('/cli-token', methods=['GET'])
def cli_token():
    """Renders the cli-token.html page"""

    provider, service = find_provider_and_service(request.args.get('id', None))

    template_values = {
        'service': provider['display'],
        'appname': settings.APP_NAME,
        'longappname': settings.SERVICE_DISPLAYNAME,
        'id': provider['id']
    }

    return render_template('cli-token.html', **template_values)


@app.route('/cli-token-login', methods=['POST'])
def cli_token_login():
    """Handler that processes cli-token login and redirects the user to the logged-in page"""

    display = 'Unknown'
    error = 'Server error, close window and try again'
    try:
        id = request.form.get('id')
        provider, service = find_provider_and_service(id)
        display = provider['display']

        try:
            # Decode the JWT
            data = request.form.get('token')
            padded_data = str(data) + "=" * (-len(data) % 4)
            content = base64.urlsafe_b64decode(padded_data)
            resp = json.loads(content)
        except:
            error = 'Error: Invalid CLI token'
            raise

        url = service['auth-url']
        # Jottacloud doesn't like the data to be urlencoded, so we send it as JSON.
        data = {
            'client_id': service['client-id'],
            'grant_type': 'password',
            'scope': provider['scope'],
            'username': resp['username'],
            'password': resp['auth_token']
        }

        try:
            response = requests.post(url, data=data, timeout=20)
            response.raise_for_status()
            content = response.content
        except requests.HTTPError as err:
            if err.response.status_code == 401:
                error = 'Error: CLI token could not be authorized, create a new and try again'
            logging.warning(f'HTTP error {err.response.status_code} on url {url} with data {data}')
            logging.warning(f'The following content was returned: {err.response.content}')
            raise err

        resp = json.loads(content)

        keyid, authid = create_authtoken(id, resp)

        fetchtoken = dbmodel.create_fetch_token(resp['id_token'])

        # If this was part of a polling request, signal completion
        dbmodel.update_fetch_token(fetchtoken, authid)

        # Report results to the user
        template_values = {
            'service': display,
            'appname': settings.APP_NAME,
            'longappname': settings.SERVICE_DISPLAYNAME,
            'authid': authid,
            'fetchtoken': fetchtoken
        }

        logging.info('Created new authid %s for service %s', keyid, id)

        return render_template('logged-in.html', **template_values)

    except:
        logging.exception(f'handler error for {display}')

        template_values = {
            'service': display,
            'appname': settings.APP_NAME,
            'longappname': settings.SERVICE_DISPLAYNAME,
            'authid': error,
            'fetchtoken': ''
        }

        return render_template('logged-in.html', **template_values)


@app.route('/fetch', methods=['GET'])
def fetch():
    """Handler that returns the authid associated with a token"""

    try:
        fetchtoken = request.args.get('token')

        # self.headers.add('Access-Control-Allow-Origin', '*')

        if fetchtoken is None or fetchtoken == '':
            return jsonify({'error': 'Missing token'})

        entry = ndb.Key(dbmodel.FetchToken, fetchtoken).get()
        if entry is None:
            return jsonify({'error': 'No such entry'})

        if entry.expires < datetime.datetime.now(datetime.timezone.utc):
            return jsonify({'error': 'No such entry'})

        if entry.authid is None or entry.authid == '':
            return jsonify({'wait': 'Not ready'})

        entry.fetched = True
        entry.put()

        return jsonify({'authid': entry.authid})
    except:
        logging.exception('handler error')
        response = jsonify({'error': 'Server error'})
        response.status_code = 500
        return response


@app.route('/token-state', methods=['GET'])
def token_state():
    """Handler to query the state of an active token"""

    try:
        fetchtoken = request.args.get('token')

        if fetchtoken is None or fetchtoken == '':
            return jsonify({'error': 'Missing token'})

        entry = ndb.Key(dbmodel.FetchToken, fetchtoken).get()
        if entry is None:
            return jsonify({'error': 'No such entry'})

        if entry.expires < datetime.datetime.now(datetime.timezone.utc):
            return jsonify({'error': 'No such entry'})

        if entry.authid is None or entry.authid == '':
            return jsonify({'wait': 'Not ready'})

        return jsonify({'success': entry.fetched})
    except:
        logging.exception('handler error')

        response = jsonify({'error': 'Server error'})
        response.status_code = 500

        return response


@app.route('/refresh', methods=['GET', 'POST'])
def refresh_handler():
    """
    Handler that retrieves a new access token,
    by decrypting the stored blob to retrieve the
    refresh token, and then requesting a new access
    token
    """
    authid = request.args.get('authid') if request.method == 'GET' else request.form.get('authid')

    if authid is None or authid == '':
        authid = request.headers.get('X-AuthID')

    servicetype = 'Unknown'

    try:
        if authid is None or authid == '':
            logging.info('No authid in query')
            response = jsonify({'error': 'No authid in query'})
            response.headers['X-Reason'] = 'No authid in query'
            response.status_code = 400
            return response


        if authid.find(':') <= 0:
            logging.info('Invalid authid in query')
            response = jsonify({'error': 'Invalid authid in query'})
            response.headers['X-Reason'] = 'Invalid authid in query'
            response.status_code = 400
            return response

        keyid = authid[:authid.index(':')]
        password = authid[authid.index(':') + 1:]

        if settings.WORKER_OFFLOAD_RATIO > random.random():
            workers = memcache.get('worker-urls')
            # logging.info('workers: %s', workers)
            if workers is not None and len(workers) > 0:
                newloc = random.choice(workers)
                logging.info('Redirecting request for id %s to %s', keyid, newloc)
                return redirect(newloc, code=302)

        if keyid == 'v2':
            return refresh_handle_v2(password)

        if settings.RATE_LIMIT > 0:

            ratelimiturl = '/ratelimit?id=' + keyid + '&adr=' + request.remote_addr
            ratelimit = memcache.get(ratelimiturl)

            if ratelimit is None:
                memcache.add(key=ratelimiturl, value=1, time=60 * 60)
            elif ratelimit > settings.RATE_LIMIT:
                logging.info('Rate limit response to: %s', keyid)
                response = jsonify({'error': 'Too many requests for this key, wait 60 minutes'})
                response.headers['X-Reason'] = 'Too many requests for this key, wait 60 minutes'
                response.status_code = 503
                return response
            else:
                memcache.incr(ratelimiturl)

        cacheurl = '/refresh?id=' + keyid + '&h=' + hashlib.sha256(password.encode('utf-8')).hexdigest()

        cached_res = memcache.get(cacheurl)
        if cached_res is not None and type(cached_res) != type(''):
            exp_secs = (int)((cached_res['expires'] - datetime.datetime.now(datetime.timezone.utc)).total_seconds())

            if exp_secs > 30:
                logging.info('Serving cached response to: %s, expires in %s secs', keyid, exp_secs)
                response = jsonify({
                    'access_token': cached_res['access_token'],
                    'expires': exp_secs,
                    'type': cached_res['type']
                })
                return response
            else:
                logging.info('Cached response to: %s is invalid because it expires in %s', keyid, exp_secs)

        # Find the entry
        entry = ndb.Key(dbmodel.AuthToken, keyid).get()
        if entry is None:
            response = jsonify({'error': 'No such key'})
            response.headers['X-Reason'] = 'No such key'
            response.status_code = 404
            return response

        servicetype = entry.service

        # Decode
        data = base64.b64decode(entry.blob)
        resp = None

        # Decrypt
        try:
            resp = json.loads(simplecrypt.decrypt(password, data).decode('utf8'))
        except:
            logging.exception('decrypt error')
            response = jsonify({'error': 'Invalid authid password'})
            response.headers['X-Reason'] = 'Invalid authid password'
            response.status_code = 400
            return response

        service = find_service(entry.service)

        # Issue a refresh request
        url = service['auth-url']
        request_params = {
            'client_id': service['client-id'],
            'grant_type': 'refresh_token',
            'refresh_token': resp['refresh_token']
        }
        if "client-secret" in service:
            request_params['client_secret'] = service['client-secret']
        if "redirect-uri" in service:
            request_params['redirect_uri'] = service['redirect-uri']

        # Some services do not allow the state to be passed
        if 'no-redirect_uri-for-refresh-request' in service and service['no-redirect_uri-for-refresh-request']:
            del request_params['redirect_uri']

        # Jottacloud doesn't like the data to be urlencoded, so we send it as JSON.
        #data = urllib.parse.urlencode(request_params)
        #if settings.TESTING:
        #    logging.info('REQ RAW: ' + str(data))

        try:
            req = requests.post(url, data=request_params, timeout=20)
            req.raise_for_status()
            content = req.content
        except requests.HTTPError as err:
            logging.error(f'PROVIDER: {servicetype}, {url}')
            logging.error(f'ERR-CODE: {err.response.status_code}')
            logging.error(f'ERR-BODY: {err.response.text}')
            if 'secret' in err.response.text.lower() or service['client-secret'] in err.response.text:
                raise err
            err_response = jsonify({'error': f'Request error: {err.response.text} (code: {err.response.status_code})'})
            err_response.headers['X-Reason'] = err.response.text
            err_response.status_code = 500
            return err_response

        # Store the old refresh_token as some servers do not send it again
        rt = resp['refresh_token']

        # Read the server response
        resp = json.loads(content)
        exp_secs = int(resp["expires_in"])

        # Set the refresh_token if it was missing
        if 'refresh_token' not in resp:
            resp['refresh_token'] = rt

        # Encrypt the updated response
        cipher = simplecrypt.encrypt(password, json.dumps(resp))
        entry.expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=exp_secs)
        entry.blob = base64.b64encode(cipher)
        entry.put()

        cached_res = {'access_token': resp['access_token'], 'expires': entry.expires, 'type': servicetype}

        memcache.set(key=cacheurl, value=cached_res, time=exp_secs - 10)
        logging.info('Caching response to: %s for %s secs, service: %s', keyid, exp_secs - 10, servicetype)

        # Write the result back to the client
        return jsonify({
            'access_token': resp['access_token'],
            'expires': exp_secs,
            'type': servicetype,
            'v2_authid': 'v2:' + entry.service + ':' + rt
        })
    except:
        logging.exception(f'handler error for {servicetype}')
        response = jsonify({'error': 'Server error'})
        response.headers['X-Reason'] = 'Server error'
        response.status_code = 500


def refresh_handle_v2(inputfragment):
    """
    Handler that retrieves a new access token,
    from the provided refresh token
    """
    servicetype = 'Unknown'
    try:
        if inputfragment.find(':') <= 0:
            response = jsonify({'error': 'Invalid authid in query'})
            response.headers['X-Reason'] = 'Invalid authid in query'
            response.status_code = 400
            return response

        servicetype = inputfragment[:inputfragment.index(':')]
        refresh_token = inputfragment[inputfragment.index(':') + 1:]

        service = find_service(servicetype)
        if service is None:
            raise Exception('No such service')

        if refresh_token is None or len(refresh_token.strip()) == 0:
            raise Exception('No token provided')

        tokenhash = hashlib.sha256(refresh_token.encode('utf-8')).hexdigest()

        if settings.RATE_LIMIT > 0:

            ratelimiturl = '/ratelimit?id=' + tokenhash + '&adr=' + request.remote_addr
            ratelimit = memcache.get(ratelimiturl)

            if ratelimit is None:
                memcache.add(key=ratelimiturl, value=1, time=60 * 60)
            elif ratelimit > settings.RATE_LIMIT:
                logging.info('Rate limit response to: %s', tokenhash)
                response = jsonify({'error': 'Too many requests for this key, wait 60 minutes'})
                response.headers['X-Reason'] = 'Too many requests for this key, wait 60 minutes'
                response.status_code = 503
                return response
            else:
                memcache.incr(ratelimiturl)

        cacheurl = '/v2/refresh?id=' + tokenhash

        cached_res = memcache.get(cacheurl)
        if cached_res is not None and type(cached_res) != type(''):
            exp_secs = (int)((cached_res['expires'] - datetime.datetime.now(datetime.timezone.utc)).total_seconds())

            if exp_secs > 30:
                logging.info('Serving cached response to: %s, expires in %s secs', tokenhash, exp_secs)
                return jsonify({
                    'access_token': cached_res['access_token'],
                    'expires': exp_secs,
                    'type': cached_res['type']
                })
            else:
                logging.info('Cached response to: %s is invalid because it expires in %s', tokenhash, exp_secs)

        url = service['auth-url']
        request_params = {
            'client_id': service['client-id'],
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        }
        if "client-secret" in service:
            request_params['client_secret'] = service['client-secret']
        if "redirect-uri" in service:
            request_params['redirect_uri'] = service['redirect-uri']

        data = urllib.parse.urlencode(request_params)

        try:
            req = requests.post(url, data=data, timeout=20)
            req.raise_for_status()
            content = req.content
        except requests.HTTPError as err:
            logging.error(f'PROVIDER: {servicetype}, {url}')
            logging.error(f'ERR-CODE: {err.response.status_code}')
            logging.error(f'ERR-BODY: {err.response.text}')
            if 'secret' in err.response.text.lower() or service['client-secret'] in err.response.text:
                raise err
            err_response = jsonify({'error': f'Request error: {err.response.text} (code: {err.response.status_code})'})
            err_response.headers['X-Reason'] = err.response.text
            err_response.status_code = 500
            return err_response

        resp = json.loads(content)
        exp_secs = int(resp["expires_in"])
        expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=exp_secs)

        cached_res = {
            'access_token': resp['access_token'],
            'expires': expires,
            'type': servicetype
        }

        memcache.set(key=cacheurl, value=cached_res, time=exp_secs - 10)
        logging.info('Caching response to: %s for %s secs, service: %s', tokenhash, exp_secs - 10, servicetype)

        # Write the result back to the client
        return jsonify({
            'access_token': resp['access_token'],
            'expires': exp_secs,
            'type': servicetype
        })

    except:
        logging.exception(f'handler error for {servicetype}')
        response = jsonify({'error': 'Server error'})
        response.headers['X-Reason'] = 'Server error'
        response.status_code = 500


@app.route('/revoke', methods=['GET'])
def revoke():
    """Renders the revoke.html page"""

    template_values = {
        'appname': settings.SERVICE_DISPLAYNAME
    }

    return render_template('revoke.html', appname=settings.SERVICE_DISPLAYNAME)


@app.route('/revoked', methods=['POST'])
def revoked():
    """Revokes an issued auth token, and renders the revoked.html page"""

    result = revoked_do_revoke()

    template_values = {
        'result': result,
        'appname': settings.SERVICE_DISPLAYNAME
    }

    return render_template('revoked.html', **template_values)

def revoked_do_revoke():
    try:
        authid = request.form.get('authid')
        if authid is None or authid == '':
            return "Error: No authid in query"

        if authid.find(':') <= 0:
            return 'Error: Invalid authid in query'

        keyid = authid[:authid.index(':')]
        password = authid[authid.index(':') + 1:]

        if keyid == 'v2':
            return 'Error: The token must be revoked from the service provider. You can de-authorize the application on the storage providers website.'

        entry = ndb.Key(dbmodel.AuthToken, keyid).get()
        if entry is None:
            return 'Error: No such user'

        data = base64.b64decode(entry.blob)
        resp = None

        try:
            resp = json.loads(simplecrypt.decrypt(password, data).decode('utf8'))
        except:
            logging.exception('decrypt error')
            return 'Error: Invalid authid password'

        entry.key.delete()
        return "Token revoked"

    except:
        logging.exception('handler error')
        return 'Error: Server error'


@app.route('/cleanup', methods=['GET'])
def cleanup():
    """Cron activated page that expires old items from the database"""

    n_fetch = 0
    n_state = 0
    n_year = 0

    # Delete all expired fetch tokens
    for n in dbmodel.FetchToken.query(dbmodel.FetchToken.expires < datetime.datetime.now(datetime.timezone.utc)):
        n_fetch += 1
        n.key.delete()

    # Delete all expired state tokens
    for n in dbmodel.StateToken.query(dbmodel.StateToken.expires < datetime.datetime.now(datetime.timezone.utc)):
        n_state += 1
        n.key.delete()

    # Delete all tokens not having seen use in a year
    one_year_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=365)
    for n in dbmodel.AuthToken.query(dbmodel.AuthToken.expires < one_year_ago):
        n_year += 1
        n.key.delete()

    return f'Cleanup done, removed {n_fetch} fetch tokens, {n_state} state tokens, and {n_year} auth tokens.'


@app.route('/export', methods=['GET'])
def export():
    """
    Handler that exports the refresh token,
    for use by the backend handlers
    """
    try:
        if len(settings.API_KEY) < 10 or request.headers['X-APIKey'] != settings.API_KEY:

            if len(settings.API_KEY) < 10:
                logging.info('No api key loaded')

            response = jsonify({'error': 'Invalid API key'})
            response.headers['X-Reason'] = 'Invalid API key'
            response.status_code = 403
            return response

        authid = request.headers['X-AuthID']

        if authid is None or authid == '':
            response = jsonify({'error': 'No authid in query'})
            response.headers['X-Reason'] = 'No authid in query'
            response.status_code = 400
            return response

        if authid.find(':') <= 0:
            response = jsonify({'error': 'Invalid authid in query'})
            response.headers['X-Reason'] = 'Invalid authid in query'
            response.status_code = 400
            return response

        keyid = authid[:authid.index(':')]
        password = authid[authid.index(':') + 1:]

        if keyid == 'v2':
            response = jsonify({'error': 'No v2 export possible'})
            response.headers['X-Reason'] = 'No v2 export possible'
            response.status_code = 400
            return response

        # Find the entry
        entry = ndb.Key(dbmodel.AuthToken, keyid).get()
        if entry is None:
            response = jsonify({'error': 'No such key'})
            response.headers['X-Reason'] = 'No such key'
            response.status_code = 404
            return response

        # Decode
        data = base64.b64decode(entry.blob)
        resp = None

        # Decrypt
        try:
            resp = json.loads(simplecrypt.decrypt(password, data).decode('utf8'))
        except:
            logging.exception('decrypt error')
            response = jsonify({'error': 'Invalid authid password'})
            response.headers['X-Reason'] = 'Invalid authid password'
            response.status_code = 400
            return response

        resp['service'] = entry.service

        logging.info('Exported %s bytes for keyid %s', len(json.dumps(resp)), keyid)

        # Write the result back to the client
        response = jsonify(resp)
        response.headers['Content-Type'] = 'application/json'
        return response
    except:
        logging.exception('handler error')
        response = jsonify({'error': 'Server error'})
        response.headers['X-Reason'] = 'Server error'
        response.status_code = 500
        return response


@app.route('/import', methods=['POST'])
def import_handler():
    """
    Handler that imports the refresh token,
    for use by the backend handlers
    """
    try:
        if len(settings.API_KEY) < 10 or request.headers['X-APIKey'] != settings.API_KEY:
            response = jsonify({'error': 'Invalid API key'})
            response.headers['X-Reason'] = 'Invalid API key'
            response.status_code = 403
            return response

        authid = request.headers['X-AuthID']

        if authid is None or authid == '':
            response = jsonify({'error': 'No authid in query'})
            response.headers['X-Reason'] = 'No authid in query'
            response.status_code = 400
            return response

        if authid.find(':') <= 0:
            response = jsonify({'error': 'Invalid authid in query'})
            response.headers['X-Reason'] = 'Invalid authid in query'
            response.status_code = 400
            return response

        keyid = authid[:authid.index(':')]
        password = authid[authid.index(':') + 1:]

        if keyid == 'v2':
            response = jsonify({'error': 'No v2 import possible'})
            response.headers['X-Reason'] = 'No v2 import possible'
            response.status_code = 400
            return response

        # Find the entry
        entry = ndb.Key(dbmodel.AuthToken, keyid).get()
        if entry is None:
            response = jsonify({'error': 'No such key'})
            response.headers['X-Reason'] = 'No such key'
            response.status_code = 404
            return response

        # Decode
        data = base64.b64decode(entry.blob)
        resp = None

        # Decrypt
        try:
            resp = json.loads(simplecrypt.decrypt(password, data).decode('utf8'))
        except:
            logging.exception('decrypt error')
            response = jsonify({'error': 'Invalid authid password'})
            response.headers['X-Reason'] = 'Invalid authid password'
            response.status_code = 400
            return response

        resp = request.get_json()
        if not 'refresh_token' in resp:
            logging.info('Import blob does not contain a refresh token')
            response = jsonify({'error': 'Import blob does not contain a refresh token'})
            response.headers['X-Reason'] = 'Import blob does not contain a refresh token'
            response.status_code = 400
            return response

        if not 'expires_in' in resp:
            logging.info('Import blob does not contain expires_in')
            response = jsonify({'error': 'Import blob does not contain expires_in'})
            response.headers['X-Reason'] = 'Import blob does not contain expires_in'
            response.status_code = 400
            return response

        logging.info('Imported %s bytes for keyid %s', len(json.dumps(resp)), keyid)

        resp['service'] = entry.service
        exp_secs = int(resp['expires_in']) - 10

        cipher = simplecrypt.encrypt(password, json.dumps(resp))
        entry.expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=exp_secs)
        entry.blob = base64.b64encode(cipher)
        entry.put()

        # Write the result back to the client
        response = jsonify(resp)
        response.headers['Content-Type'] = 'application/json'
        return response
    except:
        logging.exception('handler error')
        response = jsonify({'error': 'Server error'})
        response.headers['X-Reason'] = 'Server error'
        response.status_code = 500
        return response


@app.route('/checkalive', methods=['GET'])
def check_alive():
    """
    Handler that exports the refresh token,
    for use by the backend handlers
    """

    if settings.WORKER_URLS is None:
        return

    data = '%030x' % random.randrange(16 ** 32)

    validhosts = []

    for n in settings.WORKER_URLS:
        try:
            url = n[:-len("refresh")] + "isalive?data=" + data
            logging.info('Checking if server is alive: %s', url)

            req = requests.post(url, data=data, timeout=20)
            req.raise_for_status()
            content = req.content

            resp = json.loads(content)
            if resp["data"] != data:
                logging.info('Bad response, was %s, should have been %s', resp['data'], data)
            else:
                validhosts.append(n)
        except:
            logging.exception('handler error')

    logging.info('Valid hosts are: %s', validhosts)

    memcache.add(key='worker-urls', value=validhosts, time=60 * 60)

if __name__ == '__main__':
    app.run(debug=settings.TESTING)