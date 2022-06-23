#!/usr/bin/env python

import base64
import datetime
import hashlib
import logging
import os
import random
import urllib
import urllib2

import jinja2
import webapp2
from django.utils import simplejson as json
from google.appengine.api import memcache
from google.appengine.api import urlfetch

import dbmodel
import password_generator
import settings
import simplecrypt

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)


def wrap_json(self, obj):
    """This method helps send JSON to the client"""
    data = json.dumps(obj)
    cb = self.request.get('callback')
    if cb is None:
        cb = self.request.get('jsonp')

    if cb is not None and cb != '':
        data = cb + '(' + data + ')'
        self.response.headers['Content-Type'] = 'application/javascript'
    else:
        self.response.headers['Content-Type'] = 'application/json'

    return data


def find_provider_and_service(id):
    providers = [n for n in settings.SERVICES if n['id'] == id]
    if len(providers) != 1:
        raise Exception('No such provider: ' + id)

    provider = providers[0]
    return provider, settings.LOOKUP[provider['type']]


def find_service(id):
    id = id.lower()
    if settings.LOOKUP.has_key(id):
        return settings.LOOKUP[id]

    provider, service = find_provider_and_service(id)
    return service


def create_authtoken(provider_id, token):
    # We store the ID if we get it back
    if token.has_key("user_id"):
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
    expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=exp_secs)

    entry = None
    keyid = None

    # Find a random un-used user ID, and store the encrypted data
    while entry is None:
        keyid = '%030x' % random.randrange(16 ** 32)
        entry = dbmodel.insert_new_authtoken(keyid, user_id, b64_cipher, expires, provider_id)

    # Return the keyid and authid
    return keyid, keyid + ':' + password


class RedirectToLoginHandler(webapp2.RequestHandler):
    """Creates a state and redirects the user to the login page"""

    def get(self):
        try:
            provider, service = find_provider_and_service(self.request.get('id', None))

            # Find a random un-used state token
            stateentry = None
            while stateentry is None:
                statetoken = '%030x' % random.randrange(16 ** 32)
                stateentry = dbmodel.insert_new_statetoken(statetoken, provider['id'], self.request.get('token', None),
                                                           self.request.get('tokenversion', None))

            link = service['login-url']
            link += '?client_id=' + service['client-id']
            link += '&response_type=code'
            link += '&scope=' + provider['scope']
            link += '&state=' + statetoken
            if provider.has_key('extraurl'):
                link += '&' + provider['extraurl']
            link += '&redirect_uri=' + service['redirect-uri']

            self.redirect(link)

        except:
            logging.exception('handler error')
            self.response.set_status(500, 'Server error')
            self.response.write(wrap_json(self, {'error': 'Server error'}))


class IndexHandler(webapp2.RequestHandler):
    """Renders the index.html file with contents from settings.py"""

    def get(self):

        # If the request contains a token,
        #  register this with a limited lifetime
        #  so the caller can grab the authid automatically
        if self.request.get('token', None) is not None:
            dbmodel.create_fetch_token(self.request.get('token'))
            if settings.TESTING:
                logging.info('Created redir with token %s', self.request.get('token'))

        filtertype = self.request.get('type', None)

        tokenversion = settings.DEFAULT_TOKEN_VERSION

        try:
            if self.request.get('tokenversion') is not None:
                tokenversion = int(self.request.get('tokenversion'))
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

            if filtertype is None and n.has_key('hidden') and n['hidden']:
                continue

            link = ''
            if service.has_key('cli-token') and service['cli-token']:
                link = '/cli-token?id=' + n['id']
            else:
                link = '/login?id=' + n['id']
                if self.request.get('token', None) is not None:
                    link += '&token=' + self.request.get('token')

            if tokenversion is not None:
                link += '&tokenversion=' + str(tokenversion)

            notes = ''
            if n.has_key('notes'):
                notes = n['notes']

            brandimg = ''
            if n.has_key('brandimage'):
                brandimg = n['brandimage']

            templateitems.append({
                'display': n['display'],
                'authlink': link,
                'id': n['id'],
                'notes': notes,
                'servicelink': n['servicelink'],
                'brandimage': brandimg
            })

        template = JINJA_ENVIRONMENT.get_template('index.html')
        self.response.write(template.render({'redir': self.request.get('redirect', None), 'appname': settings.APP_NAME,
                                             'longappname': settings.SERVICE_DISPLAYNAME, 'providers': templateitems,
                                             'tokenversion': tokenversion}))


class LoginHandler(webapp2.RequestHandler):
    """
    Handles the login callback from the OAuth server
    This is called after the user grants access on the remote server
    After grabbing the refresh token, the logged-in.html page is
    rendered
    """

    def get(self, service=None):
        display = 'Unknown'
        try:
            # Grab state and code from request
            state = self.request.get('state')
            code = self.request.get('code')

            if settings.TESTING:
                logging.info('Log-in with code %s, and state %s', code, state)

            if state is None or code is None:
                raise Exception('Response is missing state or code')

            statetoken = dbmodel.StateToken.get_by_key_name(state)
            if statetoken is None:
                raise Exception('No such state found')

            if statetoken.expires < datetime.datetime.utcnow():
                raise Exception('State token has expired')

            provider, service = find_provider_and_service(statetoken.service)

            display = provider['display']

            redir_uri = service['redirect-uri']
            if self.request.get('token') is not None:
                redir_uri += self.request.get('token')

            if settings.TESTING:
                logging.info('Got log-in with url %s', redir_uri)
                logging.info('Sending to %s', service['auth-url'])

            # Some services are slow...
            urlfetch.set_default_fetch_deadline(20)

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
            if service.has_key('no-state-for-token-request') and service['no-state-for-token-request']:
                del request_params['state']

            data = urllib.urlencode(request_params)

            if settings.TESTING:
                logging.info('REQ RAW:' + data)

            headers = {'Content-Type': 'application/x-www-form-urlencoded'}

            # Alternative method for sending auth, according to HubiC API
            # if service == 'hc':
            #     logging.info('Adding header ' + v['client-id'] + ':' + v['client-secret'])
            #     headers['Authorization'] = "Basic " + base64.b64encode(v['client-id'] + ':' + v['client-secret'])

            try:
                req = urllib2.Request(url, data, headers)
                f = urllib2.urlopen(req)
                content = f.read()
                f.close()
            except urllib2.HTTPError as err:
                logging.info('ERR-CODE: ' + str(err.code))
                logging.info('ERR-BODY: ' + str(err.read()))
                raise err

            if settings.TESTING:
                logging.info('RESP RAW:' + content)

            # OAuth response is JSON
            resp = json.loads(content)

            # If this is a service that does not use refresh tokens,
            # we just return the access token to the caller
            if service.has_key('no-refresh-tokens') and service['no-refresh-tokens']:
                dbmodel.update_fetch_token(statetoken.fetchtoken, resp['access_token'])

                # Report results to the user
                template_values = {
                    'service': display,
                    'appname': settings.APP_NAME,
                    'longappname': settings.SERVICE_DISPLAYNAME,
                    'authid': resp['access_token'],
                    'fetchtoken': statetoken.fetchtoken
                }

                template = JINJA_ENVIRONMENT.get_template('logged-in.html')
                self.response.write(template.render(template_values))
                statetoken.delete()

                logging.info('Returned access token for service %s', provider['id'])
                return

            # This happens in some cases with Google's OAuth
            if not resp.has_key('refresh_token'):

                if provider.has_key('deauthlink'):
                    template_values = {
                        'service': display,
                        'authid': 'Server error, you must de-authorize ' + settings.APP_NAME,
                        'showdeauthlink': 'true',
                        'deauthlink': provider['deauthlink'],
                        'fetchtoken': ''
                    }

                    template = JINJA_ENVIRONMENT.get_template('logged-in.html')
                    self.response.write(template.render(template_values))
                    statetoken.delete()
                    return

                else:
                    raise Exception('No refresh token found, try to de-authorize the application with the provider')

            # v2 tokens are just the provider name and the refresh token
            # and they have no stored state on the server
            if statetoken.version == 2:

                if service.has_key('refresh-token-rotation') and service['refresh-token-rotation']:
                    raise Exception('Error: This service uses refresh token rotation which is not compatible with AuthID v2')

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

                template = JINJA_ENVIRONMENT.get_template('logged-in.html')
                self.response.write(template.render(template_values))
                statetoken.delete()

                logging.info('Returned refresh token for service %s', provider['id'])
                return

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

            template = JINJA_ENVIRONMENT.get_template('logged-in.html')
            self.response.write(template.render(template_values))
            statetoken.delete()

            logging.info('Created new authid %s for service %s', keyid, provider['id'])

        except:
            logging.exception('handler error for ' + display)

            template_values = {
                'service': display,
                'appname': settings.APP_NAME,
                'longappname': settings.SERVICE_DISPLAYNAME,
                'authid': 'Server error, close window and try again',
                'fetchtoken': ''
            }

            template = JINJA_ENVIRONMENT.get_template('logged-in.html')
            self.response.write(template.render(template_values))

class CliTokenHandler(webapp2.RequestHandler):
    """Renders the cli-token.html page"""

    def get(self):

        provider, service = find_provider_and_service(self.request.get('id', None))

        template_values = {
            'service': provider['display'],
            'appname': settings.APP_NAME,
            'longappname': settings.SERVICE_DISPLAYNAME,
            'id': provider['id'],
            'tokenversion': self.request.get('tokenversion', '')
        }

        template = JINJA_ENVIRONMENT.get_template('cli-token.html')
        self.response.write(template.render(template_values))


class CliTokenLoginHandler(webapp2.RequestHandler):
    """Handler that processes cli-token login and redirects the user to the logged-in page"""

    def post(self):
        display = 'Unknown'
        error = 'Server error, close window and try again'
        try:
            id = self.request.POST.get('id')
            provider, service = find_provider_and_service(id)
            display = provider['display']

            tokenversion = None
            try:
                tokenversion = int(self.request.POST.get('tokenversion'))
            except:
                pass

            try:
                data = self.request.POST.get('token')
                content = base64.urlsafe_b64decode(str(data) + '=' * (-len(data) % 4))
                resp = json.loads(content)
            except:
                error = 'Error: Invalid CLI token'
                raise Exception(error)

            urlfetch.set_default_fetch_deadline(20)
            url = service['auth-url']
            data = urllib.urlencode({
                'client_id': service['client-id'],
                'grant_type': 'password',
                'scope': provider['scope'],
                'username': resp['username'],
                'password': resp['auth_token']
            })
            try:
                req = urllib2.Request(url, data, {'Content-Type': 'application/x-www-form-urlencoded'})
                f = urllib2.urlopen(req)
                content = f.read()
                f.close()
            except urllib2.HTTPError as err:
                if err.code == 401:
                    # If trying to re-use a single-use cli token
                    error = 'Error: CLI token could not be authorized, create a new and try again'
                raise err

            resp = json.loads(content)

            # v2 tokens are just the provider name and the refresh token
            # and they have no stored state on the server
            if tokenversion == 2:

                if service.has_key('refresh-token-rotation') and service['refresh-token-rotation']:
                    error = 'Error: This service uses refresh token rotation which is not compatible with AuthID v2'
                    raise Exception(error)

                authid = 'v2:' + id + ':' + resp['refresh_token']
                fetchtoken = dbmodel.create_fetch_token(resp)
                dbmodel.update_fetch_token(fetchtoken, authid)

                # Report results to the user
                template_values = {
                    'service': display,
                    'appname': settings.APP_NAME,
                    'longappname': settings.SERVICE_DISPLAYNAME,
                    'authid': authid,
                    'fetchtoken': fetchtoken
                }

                template = JINJA_ENVIRONMENT.get_template('logged-in.html')
                self.response.write(template.render(template_values))

                logging.info('Returned refresh token for service %s', id)
                return

            keyid, authid = create_authtoken(id, resp)

            fetchtoken = dbmodel.create_fetch_token(resp)

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

            template = JINJA_ENVIRONMENT.get_template('logged-in.html')
            self.response.write(template.render(template_values))

            logging.info('Created new authid %s for service %s', keyid, id)

        except:
            logging.exception('handler error for ' + display)

            template_values = {
                'service': display,
                'appname': settings.APP_NAME,
                'longappname': settings.SERVICE_DISPLAYNAME,
                'authid': error,
                'fetchtoken': ''
            }

            template = JINJA_ENVIRONMENT.get_template('logged-in.html')
            self.response.write(template.render(template_values))


class FetchHandler(webapp2.RequestHandler):
    """Handler that returns the authid associated with a token"""

    def get(self):
        try:
            fetchtoken = self.request.get('token')

            # self.headers.add('Access-Control-Allow-Origin', '*')

            if fetchtoken is None or fetchtoken == '':
                self.response.write(wrap_json(self, {'error': 'Missing token'}))
                return

            entry = dbmodel.FetchToken.get_by_key_name(fetchtoken)
            if entry is None:
                self.response.write(wrap_json(self, {'error': 'No such entry'}))
                return

            if entry.expires < datetime.datetime.utcnow():
                self.response.write(wrap_json(self, {'error': 'No such entry'}))
                return

            if entry.authid is None or entry.authid == '':
                self.response.write(wrap_json(self, {'wait': 'Not ready'}))
                return

            entry.fetched = True
            entry.put()

            self.response.write(wrap_json(self, {'authid': entry.authid}))
        except:
            logging.exception('handler error')
            self.response.set_status(500, 'Server error')
            self.response.write(wrap_json(self, {'error': 'Server error'}))


class TokenStateHandler(webapp2.RequestHandler):
    """Handler to query the state of an active token"""

    def get(self):
        try:
            fetchtoken = self.request.get('token')

            if fetchtoken is None or fetchtoken == '':
                self.response.write(wrap_json(self, {'error': 'Missing token'}))
                return

            entry = dbmodel.FetchToken.get_by_key_name(fetchtoken)
            if entry is None:
                self.response.write(wrap_json(self, {'error': 'No such entry'}))
                return

            if entry.expires < datetime.datetime.utcnow():
                self.response.write(wrap_json(self, {'error': 'No such entry'}))
                return

            if entry.authid is None or entry.authid == '':
                self.response.write(wrap_json(self, {'wait': 'Not ready'}))
                return

            self.response.write(wrap_json(self, {'success': entry.fetched}))
        except:
            logging.exception('handler error')
            self.response.set_status(500, 'Server error')
            self.response.write(wrap_json(self, {'error': 'Server error'}))


class RefreshHandler(webapp2.RequestHandler):
    """
    Handler that retrieves a new access token,
    by decrypting the stored blob to retrieve the
    refresh token, and then requesting a new access
    token
    """

    def get(self):
        authid = self.request.get('authid')

        if authid is None or authid == '':
            authid = self.request.headers['X-AuthID']

        return self.process(authid)

    def post(self):
        authid = self.request.POST.get('authid')

        if authid is None or authid == '':
            authid = self.request.headers['X-AuthID']

        return self.process(authid)

    def process(self, authid):

        servicetype = 'Unknown'

        try:

            if authid is None or authid == '':
                logging.info('No authid in query')
                self.response.headers['X-Reason'] = 'No authid in query'
                self.response.set_status(400, 'No authid in query')
                return

            if authid.find(':') <= 0:
                logging.info('Invalid authid in query')
                self.response.headers['X-Reason'] = 'Invalid authid in query'
                self.response.set_status(400, 'Invalid authid in query')
                return

            keyid = authid[:authid.index(':')]
            password = authid[authid.index(':') + 1:]

            if settings.WORKER_OFFLOAD_RATIO > random.random():
                workers = memcache.get('worker-urls')
                # logging.info('workers: %s', workers)
                if workers is not None and len(workers) > 0:
                    newloc = random.choice(workers)
                    logging.info('Redirecting request for id %s to %s', keyid, newloc)
                    self.response.headers['Location'] = newloc
                    self.response.set_status(302, 'Found')
                    return

            if keyid == 'v2':
                self.handle_v2(password)
                return

            if settings.RATE_LIMIT > 0:

                ratelimiturl = '/ratelimit?id=' + keyid + '&adr=' + self.request.remote_addr
                ratelimit = memcache.get(ratelimiturl)

                if ratelimit is None:
                    memcache.add(key=ratelimiturl, value=1, time=60 * 60)
                elif ratelimit > settings.RATE_LIMIT:
                    logging.info('Rate limit response to: %s', keyid)
                    self.response.headers['X-Reason'] = 'Too many request for this key, wait 60 minutes'
                    self.response.set_status(503, 'Too many request for this key, wait 60 minutes')
                    return
                else:
                    memcache.incr(ratelimiturl)

            cacheurl = '/refresh?id=' + keyid + '&h=' + hashlib.sha256(password).hexdigest()

            cached_res = memcache.get(cacheurl)
            if cached_res is not None and type(cached_res) != type(''):
                exp_secs = (int)((cached_res['expires'] - datetime.datetime.utcnow()).total_seconds())

                if exp_secs > 30:
                    logging.info('Serving cached response to: %s, expires in %s secs', keyid, exp_secs)
                    self.response.write(json.dumps(
                        {'access_token': cached_res['access_token'], 'expires': exp_secs, 'type': cached_res['type']}))
                    return
                else:
                    logging.info('Cached response to: %s is invalid because it expires in %s', keyid, exp_secs)

            # Find the entry
            entry = dbmodel.AuthToken.get_by_key_name(keyid)
            if entry is None:
                self.response.headers['X-Reason'] = 'No such key'
                self.response.set_status(404, 'No such key')
                return

            servicetype = entry.service

            # Decode
            data = base64.b64decode(entry.blob)
            resp = None

            # Decrypt
            try:
                resp = json.loads(simplecrypt.decrypt(password, data).decode('utf8'))
            except:
                logging.exception('decrypt error')
                self.response.headers['X-Reason'] = 'Invalid authid password'
                self.response.set_status(400, 'Invalid authid password')
                return

            service = find_service(entry.service)

            # Issue a refresh request
            url = service['auth-url']
            request_params = {
                'client_id': service['client-id'],
                'grant_type': 'refresh_token',
                'refresh_token': resp['refresh_token']
            }
            if service.has_key("client-secret"):
                request_params['client_secret'] = service['client-secret']
            if service.has_key("redirect-uri"):
                request_params['redirect_uri'] = service['redirect-uri']

            # Some services do not allow the state to be passed
            if service.has_key('no-redirect_uri-for-refresh-request') and service['no-redirect_uri-for-refresh-request']:
                del request_params['redirect_uri']

            data = urllib.urlencode(request_params)
            if settings.TESTING:
                logging.info('REQ RAW: ' + str(data))
            urlfetch.set_default_fetch_deadline(20)

            try:
                req = urllib2.Request(url, data, {'Content-Type': 'application/x-www-form-urlencoded'})
                f = urllib2.urlopen(req)
                content = f.read()
                f.close()
            except urllib2.HTTPError as err:
                logging.info('ERR-CODE: ' + str(err.code))
                logging.info('ERR-BODY: ' + str(err.read()))
                raise err

            # Store the old refresh_token as some servers do not send it again
            rt = resp['refresh_token']

            # Read the server response
            resp = json.loads(content)
            exp_secs = int(resp["expires_in"])

            # Set the refresh_token if it was missing
            if not resp.has_key('refresh_token'):
                resp['refresh_token'] = rt

            # Encrypt the updated response
            cipher = simplecrypt.encrypt(password, json.dumps(resp))
            entry.expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=exp_secs)
            entry.blob = base64.b64encode(cipher)
            entry.put()

            cached_res = {'access_token': resp['access_token'], 'expires': entry.expires, 'type': servicetype}

            memcache.set(key=cacheurl, value=cached_res, time=exp_secs - 10)
            logging.info('Caching response to: %s for %s secs, service: %s', keyid, exp_secs - 10, servicetype)

            # Write the result back to the client
            if service.has_key('refresh-token-rotation') and service['refresh-token-rotation']:
                self.response.write(json.dumps(
                    {'access_token': resp['access_token'], 'expires': exp_secs, 'type': servicetype}))
            else:
                self.response.write(json.dumps(
                    {'access_token': resp['access_token'], 'expires': exp_secs, 'type': servicetype,
                    'v2_authid': 'v2:' + entry.service + ':' + rt}))

        except:
            logging.exception('handler error for ' + servicetype)
            self.response.headers['X-Reason'] = 'Server error'
            self.response.set_status(500, 'Server error')

    def post(self):
        self.get()

    """
    Handler that retrieves a new access token,
    from the provided refresh token
    """

    def handle_v2(self, inputfragment):
        servicetype = 'Unknown'
        try:
            if inputfragment.find(':') <= 0:
                self.response.headers['X-Reason'] = 'Invalid authid in query'
                self.response.set_status(400, 'Invalid authid in query')
                return

            servicetype = inputfragment[:inputfragment.index(':')]
            refresh_token = inputfragment[inputfragment.index(':') + 1:]

            service = find_service(servicetype)
            if service is None:
                raise Exception('No such service')

            if refresh_token is None or len(refresh_token.strip()) == 0:
                raise Exception('No token provided')

            tokenhash = hashlib.md5(refresh_token).hexdigest()

            if settings.RATE_LIMIT > 0:

                ratelimiturl = '/ratelimit?id=' + tokenhash + '&adr=' + self.request.remote_addr
                ratelimit = memcache.get(ratelimiturl)

                if ratelimit is None:
                    memcache.add(key=ratelimiturl, value=1, time=60 * 60)
                elif ratelimit > settings.RATE_LIMIT:
                    logging.info('Rate limit response to: %s', tokenhash)
                    self.response.headers['X-Reason'] = 'Too many request for this key, wait 60 minutes'
                    self.response.set_status(503, 'Too many request for this key, wait 60 minutes')
                    return
                else:
                    memcache.incr(ratelimiturl)

            cacheurl = '/v2/refresh?id=' + tokenhash

            cached_res = memcache.get(cacheurl)
            if cached_res is not None and type(cached_res) != type(''):
                exp_secs = (int)((cached_res['expires'] - datetime.datetime.utcnow()).total_seconds())

                if exp_secs > 30:
                    logging.info('Serving cached response to: %s, expires in %s secs', tokenhash, exp_secs)
                    self.response.write(json.dumps(
                        {'access_token': cached_res['access_token'], 'expires': exp_secs, 'type': cached_res['type']}))
                    return
                else:
                    logging.info('Cached response to: %s is invalid because it expires in %s', tokenhash, exp_secs)

            url = service['auth-url']
            request_params = {
                'client_id': service['client-id'],
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token
            }
            if service.has_key("client-secret"):
                request_params['client_secret'] = service['client-secret']
            if service.has_key("redirect-uri"):
                request_params['redirect_uri'] = service['redirect-uri']

            data = urllib.urlencode(request_params)

            urlfetch.set_default_fetch_deadline(20)

            req = urllib2.Request(url, data, {'Content-Type': 'application/x-www-form-urlencoded'})
            f = urllib2.urlopen(req)
            content = f.read()
            f.close()

            resp = json.loads(content)
            exp_secs = int(resp["expires_in"])
            expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=exp_secs)

            cached_res = {'access_token': resp['access_token'], 'expires': expires, 'type': servicetype}

            memcache.set(key=cacheurl, value=cached_res, time=exp_secs - 10)
            logging.info('Caching response to: %s for %s secs, service: %s', tokenhash, exp_secs - 10, servicetype)

            # Write the result back to the client
            self.response.write(
                json.dumps({'access_token': resp['access_token'], 'expires': exp_secs, 'type': servicetype}))

        except:
            logging.exception('handler error for ' + servicetype)
            self.response.headers['X-Reason'] = 'Server error'
            self.response.set_status(500, 'Server error')


class RevokeHandler(webapp2.RequestHandler):
    """Renders the revoke.html page"""

    def get(self):
        template_values = {
            'appname': settings.SERVICE_DISPLAYNAME
        }

        template = JINJA_ENVIRONMENT.get_template('revoke.html')
        self.response.write(template.render(template_values))


class RevokedHandler(webapp2.RequestHandler):
    """Revokes an issued auth token, and renders the revoked.html page"""

    def do_revoke(self):
        try:
            authid = self.request.get('authid')
            if authid is None or authid == '':
                return "Error: No authid in query"

            if authid.find(':') <= 0:
                return 'Error: Invalid authid in query'

            keyid = authid[:authid.index(':')]
            password = authid[authid.index(':') + 1:]

            if keyid == 'v2':
                return 'Error: The token must be revoked from the service provider. You can de-authorize the application on the storage providers website.'

            entry = dbmodel.AuthToken.get_by_key_name(keyid)
            if entry is None:
                return 'Error: No such user'

            data = base64.b64decode(entry.blob)
            resp = None

            try:
                resp = json.loads(simplecrypt.decrypt(password, data).decode('utf8'))
            except:
                logging.exception('decrypt error')
                return 'Error: Invalid authid password'

            entry.delete()
            return "Token revoked"

        except:
            logging.exception('handler error')
            return 'Error: Server error'

    def post(self):
        result = self.do_revoke()

        template_values = {
            'result': result,
            'appname': settings.SERVICE_DISPLAYNAME
        }

        template = JINJA_ENVIRONMENT.get_template('revoked.html')
        self.response.write(template.render(template_values))


class CleanupHandler(webapp2.RequestHandler):
    """Cron activated page that expires old items from the database"""

    def get(self):
        # Delete all expired fetch tokens
        for n in dbmodel.FetchToken.gql('WHERE expires < :1', datetime.datetime.utcnow()):
            n.delete()

        # Delete all expired state tokens
        for n in dbmodel.StateToken.gql('WHERE expires < :1', datetime.datetime.utcnow()):
            n.delete()

        # Delete all tokens not having seen use in a year
        for n in dbmodel.AuthToken.gql('WHERE expires < :1',
                                       (datetime.datetime.utcnow() + datetime.timedelta(days=-365))):
            n.delete()


class ExportHandler(webapp2.RequestHandler):
    """
    Handler that exports the refresh token,
    for use by the backend handlers
    """

    def get(self):

        try:
            if len(settings.API_KEY) < 10 or self.request.headers['X-APIKey'] != settings.API_KEY:

                if len(settings.API_KEY) < 10:
                    logging.info('No api key loaded')

                self.response.headers['X-Reason'] = 'Invalid API key'
                self.response.set_status(403, 'Invalid API key')
                return

            authid = self.request.headers['X-AuthID']

            if authid is None or authid == '':
                self.response.headers['X-Reason'] = 'No authid in query'
                self.response.set_status(400, 'No authid in query')
                return

            if authid.find(':') <= 0:
                self.response.headers['X-Reason'] = 'Invalid authid in query'
                self.response.set_status(400, 'Invalid authid in query')
                return

            keyid = authid[:authid.index(':')]
            password = authid[authid.index(':') + 1:]

            if keyid == 'v2':
                self.response.headers['X-Reason'] = 'No v2 export possible'
                self.response.set_status(400, 'No v2 export possible')
                return

            # Find the entry
            entry = dbmodel.AuthToken.get_by_key_name(keyid)
            if entry is None:
                self.response.headers['X-Reason'] = 'No such key'
                self.response.set_status(404, 'No such key')
                return

            # Decode
            data = base64.b64decode(entry.blob)
            resp = None

            # Decrypt
            try:
                resp = json.loads(simplecrypt.decrypt(password, data).decode('utf8'))
            except:
                logging.exception('decrypt error')
                self.response.headers['X-Reason'] = 'Invalid authid password'
                self.response.set_status(400, 'Invalid authid password')
                return

            resp['service'] = entry.service

            logging.info('Exported %s bytes for keyid %s', len(json.dumps(resp)), keyid)

            # Write the result back to the client
            self.response.headers['Content-Type'] = 'application/json'
            self.response.write(json.dumps(resp))
        except:
            logging.exception('handler error')
            self.response.headers['X-Reason'] = 'Server error'
            self.response.set_status(500, 'Server error')


class ImportHandler(webapp2.RequestHandler):
    """
    Handler that imports the refresh token,
    for use by the backend handlers
    """

    def post(self):

        try:
            if len(settings.API_KEY) < 10 or self.request.headers['X-APIKey'] != settings.API_KEY:
                self.response.headers['X-Reason'] = 'Invalid API key'
                self.response.set_status(403, 'Invalid API key')
                return

            authid = self.request.headers['X-AuthID']

            if authid is None or authid == '':
                self.response.headers['X-Reason'] = 'No authid in query'
                self.response.set_status(400, 'No authid in query')
                return

            if authid.find(':') <= 0:
                self.response.headers['X-Reason'] = 'Invalid authid in query'
                self.response.set_status(400, 'Invalid authid in query')
                return

            keyid = authid[:authid.index(':')]
            password = authid[authid.index(':') + 1:]

            if keyid == 'v2':
                self.response.headers['X-Reason'] = 'No v2 import possible'
                self.response.set_status(400, 'No v2 import possible')
                return

            # Find the entry
            entry = dbmodel.AuthToken.get_by_key_name(keyid)
            if entry is None:
                self.response.headers['X-Reason'] = 'No such key'
                self.response.set_status(404, 'No such key')
                return

            # Decode
            data = base64.b64decode(entry.blob)
            resp = None

            # Decrypt
            try:
                resp = json.loads(simplecrypt.decrypt(password, data).decode('utf8'))
            except:
                logging.exception('decrypt error')
                self.response.headers['X-Reason'] = 'Invalid authid password'
                self.response.set_status(400, 'Invalid authid password')
                return

            resp = json.loads(self.request.body)
            if not 'refresh_token' in resp:
                logging.info('Import blob does not contain a refresh token')
                self.response.headers['X-Reason'] = 'Import blob does not contain a refresh token'
                self.response.set_status(400, 'Import blob does not contain a refresh token')
                return

            if not 'expires_in' in resp:
                logging.info('Import blob does not contain expires_in')
                self.response.headers['X-Reason'] = 'Import blob does not contain expires_in'
                self.response.set_status(400, 'Import blob does not contain expires_in')
                return

            logging.info('Imported %s bytes for keyid %s', len(json.dumps(resp)), keyid)

            resp['service'] = entry.service
            exp_secs = int(resp['expires_in']) - 10

            cipher = simplecrypt.encrypt(password, json.dumps(resp))
            entry.expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=exp_secs)
            entry.blob = base64.b64encode(cipher)
            entry.put()

            # Write the result back to the client
            self.response.headers['Content-Type'] = 'application/json'
            self.response.write(json.dumps(resp))
        except:
            logging.exception('handler error')
            self.response.headers['X-Reason'] = 'Server error'
            self.response.set_status(500, 'Server error')


class CheckAliveHandler(webapp2.RequestHandler):
    """
    Handler that exports the refresh token,
    for use by the backend handlers
    """

    def get(self):
        if settings.WORKER_URLS is None:
            return

        data = '%030x' % random.randrange(16 ** 32)

        validhosts = []

        for n in settings.WORKER_URLS:
            try:
                url = n[:-len("refresh")] + "isalive?data=" + data
                logging.info('Checking if server is alive: %s', url)

                req = urllib2.Request(url)
                f = urllib2.urlopen(req)
                content = f.read()
                f.close()

                resp = json.loads(content)
                if resp["data"] != data:
                    logging.info('Bad response, was %s, should have been %s', resp['data'], data)
                else:
                    validhosts.append(n)
            except:
                logging.exception('handler error')

        logging.info('Valid hosts are: %s', validhosts)

        memcache.add(key='worker-urls', value=validhosts, time=60 * 60 * 1)


app = webapp2.WSGIApplication([
    ('/logged-in', LoginHandler),
    ('/login', RedirectToLoginHandler),
    ('/cli-token', CliTokenHandler),
    ('/cli-token-login', CliTokenLoginHandler),
    ('/refresh', RefreshHandler),
    ('/fetch', FetchHandler),
    ('/token-state', TokenStateHandler),
    ('/revoked', RevokedHandler),
    ('/revoke', RevokeHandler),
    ('/cleanup', CleanupHandler),
    ('/export', ExportHandler),
    ('/import', ImportHandler),
    ('/checkalive', CheckAliveHandler),
    (r'/.*', IndexHandler)
], debug=settings.TESTING)
