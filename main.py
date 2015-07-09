#!/usr/bin/env python

import logging

import os
import urllib
import urllib2
import base64

import webapp2
import jinja2
import settings

from django.utils import simplejson as json

import simplecrypt
import password_generator

import dbmodel
import datetime
import random

from google.appengine.api import urlfetch

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)


def wrap_json(self, obj):
    """This method helps send JSON to the client"""
    data = json.dumps(obj)
    cb = self.request.get('callback')
    if cb == None:
        cb = self.request.get('jsonp')

    if cb != None and cb != '':
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



class RedirectToLoginHandler(webapp2.RequestHandler):
    """Creates a state and redirects the user to the login page"""

    def get(self):
        try:
            provider, service = find_provider_and_service(self.request.get('id', None))

            # Find a random un-used state token
            stateentry = None
            while stateentry == None:
                statetoken = '%030x' % random.randrange(16**32)
                stateentry = dbmodel.insert_new_statetoken(statetoken, provider['id'], self.request.get('token', None))

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
        if self.request.get('token', None) != None:
            dbmodel.create_fetch_token(self.request.get('token'))        
            if settings.TESTING:
                logging.info('Created redir with token %s', self.request.get('token'))

        filtertype = self.request.get('type', None)

        templateitems = []
        for n in settings.SERVICES:
            service = settings.LOOKUP[n['type']]

            # If there is a ?type= parameter, filter the results
            if filtertype != None and filtertype != n['id']:
                continue

            # If the client id is invalid or missing, skip the entry
            if service['client-id'] == None or service['client-id'][0:8] == 'XXXXXXXX':
                continue
            
            redir_uri = service['redirect-uri']

            link = '/login?id=' + n['id']
            if self.request.get('token', None) != None:
                link += '&token=' + self.request.get('token')

            notes = ''
            if n.has_key('notes'):
                notes = n['notes']

            templateitems.append({
                'display': n['display'],
                'authlink': link,
                'id': n['id'],
                'notes': notes,
                'servicelink': n['servicelink']
            })

        template = JINJA_ENVIRONMENT.get_template('index.html')
        self.response.write(template.render({'redir': self.request.get('redirect', None), 'appname': settings.APP_NAME, 'longappname': settings.SERVICE_DISPLAYNAME, 'providers': templateitems}))


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

            if state == None or code == None:
                raise Exception('Response is missing state or code')

            statetoken = dbmodel.StateToken.get_by_key_name(state)
            if statetoken == None:
                raise Exception('No such state found')

            if statetoken.expires < datetime.datetime.utcnow():
                raise Exception('State token has expired')

            provider, service = find_provider_and_service(statetoken.service)

            display = provider['display']

            redir_uri = service['redirect-uri']
            if self.request.get('token') != None:
                redir_uri += self.request.get('token')

            if settings.TESTING:
                logging.info('Got log-in with url %s', redir_uri)
                logging.info('Sending to %s', service['auth-url'])

            # Some services are slow...
            urlfetch.set_default_fetch_deadline(20)


            # With the returned code, request a refresh and access token
            url = service['auth-url']
            data = urllib.urlencode({'client_id' : service['client-id'],
                                     'redirect_uri'  : redir_uri,
                                     'client_secret': service['client-secret'],
                                     'code': code,
                                     'state': state,
                                     'grant_type': 'authorization_code'
                                     })

            headers = {'Content-Type': 'application/x-www-form-urlencoded'}

            # Alternative method for sending auth, according to HubiC API
            #if service == 'hc':
            #     logging.info('Adding header ' + v['client-id'] + ':' + v['client-secret'])
            #     headers['Authorization'] = "Basic " + base64.b64encode(v['client-id'] + ':' + v['client-secret'])

            req = urllib2.Request(url, data, headers)
            f = urllib2.urlopen(req)
            content = f.read()
            f.close()

            if settings.TESTING:
                logging.info('RESP RAW:' + content)

            # OAuth response is JSON
            resp = json.loads(content)

            # This happens in some cases with Google's OAuth
            if not resp.has_key('refresh_token'):
                template_values = {
                    'service': display,
                    'authid':  'Server error, you must de-authorize Duplicati',
                    'deauthlink': 'true',
                    'fetchtoken': ''
                }

                template = JINJA_ENVIRONMENT.get_template('logged-in.html')
                self.response.write(template.render(template_values))
                statetoken.delete()
                return        


            # We store the ID if we get it back
            if resp.has_key("user_id"):
                user_id = resp["user_id"]
            else:
                user_id = "N/A"

            exp_secs = int(resp["expires_in"])

            # Create a random password and encrypt the response
            # This ensures that a hostile takeover will not get access
            #  to stored access and refresh tokens
            password = password_generator.generate_pass()
            cipher = simplecrypt.encrypt(password, json.dumps(resp))

            # Convert to text and prepare for storage
            b64_cipher = base64.b64encode(cipher)
            expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=exp_secs)
            fetchtoken = statetoken.fetchtoken

            entry = None
            keyid = None

            # Find a random un-used user ID, and store the encrypted data
            while entry == None:
                keyid = '%030x' % random.randrange(16**32)
                entry = dbmodel.insert_new_authtoken(keyid, user_id, b64_cipher, expires, provider['id'])

            # Return the id and password to the user
            authid = keyid + ':' + password

            # If this was part of a polling request, signal completion
            dbmodel.update_fetch_token(fetchtoken, authid)

            # Report results to the user
            template_values = {
                'service': display,
                'appname': settings.APP_NAME,
                'longappname': settings.SERVICE_DISPLAYNAME,
                'authid':  authid,
                'fetchtoken': fetchtoken
            }

            template = JINJA_ENVIRONMENT.get_template('logged-in.html')
            self.response.write(template.render(template_values))
            statetoken.delete()

        except:
            logging.exception('handler error for ' + display)

            template_values = {
                'service': display,
                'appname': settings.APP_NAME,
                'longappname': settings.SERVICE_DISPLAYNAME,
                'authid':  'Server error, close window and try again',
                'fetchtoken': ''
            }

            template = JINJA_ENVIRONMENT.get_template('logged-in.html')
            self.response.write(template.render(template_values))      

        
class FetchHandler(webapp2.RequestHandler):
    
    """Handler that returns the authid associated with a token"""

    def get(self):
        try:
            fetchtoken = self.request.get('token')

            #self.headers.add('Access-Control-Allow-Origin', '*')

            if fetchtoken == None or fetchtoken == '':
                self.response.write(wrap_json(self, {'error': 'Missing token'}))
                return

            entry = dbmodel.FetchToken.get_by_key_name(fetchtoken)
            if entry == None:
                self.response.write(wrap_json(self, {'error': 'No such entry'}))
                return

            if entry.expires < datetime.datetime.utcnow():
                self.response.write(wrap_json(self, {'error': 'No such entry'}))
                return

            if entry.authid == None or entry.authid == '':
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

            if fetchtoken == None or fetchtoken == '':
                self.response.write(wrap_json(self, {'error': 'Missing token'}))
                return

            entry = dbmodel.FetchToken.get_by_key_name(fetchtoken)
            if entry == None:
                self.response.write(wrap_json(self, {'error': 'No such entry'}))
                return

            if entry.expires < datetime.datetime.utcnow():
                self.response.write(wrap_json(self, {'error': 'No such entry'}))
                return

            if entry.authid == None or entry.authid == '':
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

        servicetype = 'Unknown'

        try:
            authid = self.request.get('authid')

            if authid == None or authid == '':
                authid = self.request.headers['X-AuthID']

            if authid == None or authid == '':
                self.response.headers['X-Reason'] = 'No authid in query'
                self.response.set_status(400)
                return

            if authid.find(':') <= 0:
                self.response.headers['X-Reason'] = 'Invalid authid in query'
                self.response.set_status(400)
                return

            keyid = authid[:authid.index(':')]
            password = authid[authid.index(':')+1:]

            # Find the entry
            entry = dbmodel.AuthToken.get_by_key_name(keyid)
            if entry == None:
                self.response.headers['X-Reason'] = 'No such user'
                self.response.set_status(404)
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
                self.response.set_status(400)
                return

            service = find_service(entry.service)

            # Issue a refresh request
            url = service['auth-url']
            data = urllib.urlencode({'client_id' : service['client-id'],
                                     'redirect_uri'  : service['redirect-uri'],
                                     'client_secret': service['client-secret'],
                                     'grant_type': 'refresh_token',
                                     'refresh_token': resp['refresh_token']
                                     })

            urlfetch.set_default_fetch_deadline(20)

            req = urllib2.Request(url, data, {'Content-Type': 'application/x-www-form-urlencoded'})
            f = urllib2.urlopen(req)
            content = f.read()
            f.close()

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

            # Write the result back to the client
            self.response.write(json.dumps({'access_token': resp['access_token'], 'expires': exp_secs, 'type': servicetype}))

        except:
            logging.exception('handler error for ' + servicetype)
            self.response.headers['X-Reason'] = 'Server error'
            self.response.set_status(500)

    def post(self):
        self.get()        

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
            if authid == None or authid == '':
                return "Error: No authid in query"

            if authid.find(':') <= 0:
                return 'Error: Invalid authid in query'

            keyid = authid[:authid.index(':')]
            password = authid[authid.index(':')+1:]

            entry = dbmodel.AuthToken.get_by_key_name(keyid)
            if entry == None:
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
                'result':  result,
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
        for n in dbmodel.AuthToken.gql('WHERE expires < :1', (datetime.datetime.utcnow() + datetime.timedelta(days=-365))):
            n.delete()


app = webapp2.WSGIApplication([
    ('/logged-in', LoginHandler),
    ('/login', RedirectToLoginHandler),
    ('/refresh', RefreshHandler),
    ('/fetch', FetchHandler),
    ('/token-state', TokenStateHandler),
    ('/revoked', RevokedHandler),    
    ('/revoke', RevokeHandler),    
    ('/cleanup', CleanupHandler),    
    (r'/.*', IndexHandler)
], debug=settings.TESTING)
