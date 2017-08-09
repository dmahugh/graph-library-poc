"""Common auth functionality used by both web apps and service apps."""
import base64
import json
import os
import pprint
import time
import urllib.parse
import uuid
import warnings
import webbrowser

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bottle import redirect, request

class GraphConnection(object):
    """Abstract base class for Graph connections. Contains functionality common
    to both web apps and service apps."""

    def __init__(self):
        """Initialize configuration properties. This method should be called in
        the __init__() iof subclasses with super().__init__()."""

        # configuration settings
        self.config = dict(api_base='',
                           app_id='',
                           app_name='',
                           app_secret='',
                           auth_base='',
                           grant_type='',
                           redirect_uri='',
                           scope='',
                           scopes=[],
                           tenant_id='',
                           token_url='',
                           verbose=True)

        # session state properties
        self.state = dict(access_token=None,
                          refresh_token=None,
                          token_expires_at=0,
                          auth_url='',
                          authcode='',
                          authstate='',
                          token_type='',
                          token_scope='',
                          loggedin=False)
        self.photo = None
        self.me = dict()

        # allow use of http:// for redirect URIs
        warnings.filterwarnings("ignore", category=InsecureRequestWarning)

    def api_endpoint(self, url):
        """Convert relative endpoint to full URL."""
        if url.split('/')[0].lower() in ['http:', 'https:']:
            return url
        else:
            return urllib.parse.urljoin(self.config['api_base'], url.lstrip('/'))

    def delete(self, url, headers=None, data=None, verify=False, params=None):
        """Wrapper for authenticated HTTP DELETE to API endpoint.

        verify = the Requests option for verifying SSL certificate; defaults
                 to False for demo purposes. For more information see:
        http://docs.python-requests.org/en/master/user/advanced/#ssl-csert-verification
        """
        self.token_validation()
        return requests.delete(self.api_endpoint(url),
                               headers=self.http_request_headers(headers),
                               data=data, verify=verify, params=params)

    def get(self, endpoint, headers=None, stream=False, jsononly=False):
        """Wrapper for authenticated HTTP GET from API endpoint.
        endpoint = absolute or relative URL (e.g., "me/contacts")
        headers = dictionary of HTTP request headers, can override the defaults
                  returned by http_request_headers()
        stream = Requests stream argument; e.g., use True for image data
        jsononly = if True, the JSON 'value' is returned instead of the response
                   object
        """
        self.token_validation()
        response = requests.get(self.api_endpoint(endpoint),
                                headers=self.http_request_headers(headers),
                                stream=stream)
        if jsononly:
            return response.json().get('value', None)
        else:
            return response

    def http_request_headers(self, headers=None):
        """Returns dictionary of the default HTTP headers used for calls to
        the Graph API, including current access token and a unique identifier
        that can be used to correlate requests and responses when needed.
        headers = optional additional headers or overrides for the default
                  headers, to be merged into returned dictionary
        """
        merged_headers = { \
            'User-Agent' : 'graphhelper-alpha',
            'Authorization' : 'Bearer {0}'.format(self.state['access_token']),
            'Accept' : 'application/json',
            'Content-Type' : 'application/json',
            'client-request-id' : str(uuid.uuid4()), # unique identifier
            'return-client-request-id' : 'true'}
        if headers:
            merged_headers.update(headers)
        return merged_headers

    def patch(self, url, headers=None, data=None, verify=False, params=None):
        """Wrapper for authenticated HTTP PATCH to API endpoint.

        verify = the Requests option for verifying SSL certificate; defaults
                 to False for demo purposes. For more information see:
        http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification
        """
        self.token_validation()
        return requests.patch(self.api_endpoint(url),
                              headers=self.http_request_headers(headers),
                              data=data, verify=verify, params=params)

    def post(self, url, headers=None, data=None, verify=False, params=None):
        """Wrapper for authenticated HTTP POST to API endpoint.

        verify = the Requests option for verifying SSL certificate; defaults
                 to False for demo purposes. For more information see:
        http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification
        """
        self.token_validation()
        return requests.post(self.api_endpoint(url),
                             headers=self.http_request_headers(headers),
                             data=data, verify=verify, params=params)

    def print_msg(self, msg):
        """Print message to console if self.config['verbose']."""
        if self.config['verbose']:
            print(msg)

    def print_settings(self):
        """Print current property values to console (for diagnostics)."""
        self.print_msg(' -> graphhelper.GraphConnection properties ...')
        pprint.pprint(self.__dict__)

    def refresh_access_token(self):
        """Refresh the current access token."""
        response = requests.post(self.config['token_url'], \
            data=dict(client_id=self.config['app_id'],
                      client_secret=self.config['app_secret'],
                      grant_type='refresh_token',
                      refresh_token=self.state['refresh_token']))
        self.save_token(response)

    def save_token(self, response):
        """Parse a retrieved access token out of the response from the token
        endpoint, save the access token and related metadata.

        response = response object returned by self.config['token_url'] endpoint

        Returns True if the token was successfully saved, False if not.
        """
        # this functionality is currently implemented in subclasses; consider
        # whether this can be handled here in a generic manner for all
        # supported auth types
        pass

    def token_abbrev(self, token_val=None, token_type='access'):
        """Return abbreviated version of an access token for display purposes.

        If a token_val is provided, that value is is abbreviated.

        If no token_val is provided, the type argument determines the value:
        type == 'access' (default) - self.state['access_token']
        type == 'refresh' - self.state['refresh_token']
        """
        if token_val:
            token = token_val # token value passed as a parameter
        else:
            # no token value provided
            if token_type.lower() == 'refresh':
                token = self.state['refresh_token']
            else:
                token = self.state['access_token']
        if token:
            return token[:3] + '...' + token[-3:] + ' ({0} bytes)'. \
                format(len(token))
        else:
            return 'None'

    def token_seconds(self):
        """Return number of seconds until current access token will expire."""
        if not self.state['access_token'] or \
            time.time() >= self.state['token_expires_at']:
            return 0
        return int(self.state['token_expires_at'] - time.time())

    def token_validation(self, nseconds=5):
        """Verify that current access token is valid for at least nseconds, and
        if not then attempt to refresh it."""
        if self.token_seconds() < nseconds:
            self.refresh_access_token()

class AppConnect(GraphConnection):
    """Connection class for app-only authentication with Microsoft Graph.

    Implements the OAuth 2.0 Client Credentials "2-legged OAuth" workflow,
    as documented here: https://tools.ietf.org/html/rfc6749#section-4.4
    """
    def __init__(self, config=None):
        """
        config = configuration settings dictionary

        If config dictionary contains a configfile entry, settings are loaded
        from that JSON file first, then other entries in the config dictionary
        may ovveride those settings if desired.
        """

        super().__init__() # base class initialization

        if not config:
            # if no config settings provided, read default config file
            config = {'configfile': 'config/service.json'}
        if 'configfile' in config:
            # merge settings from config file. Explicit settings in the config
            # object are retained (take precedence over config file entries)
            filesettings = json.loads(open(config['configfile']).read())
            for key in filesettings:
                if key not in config:
                    config[key] = filesettings[key]

        # store settings
        if 'app_name' in config:
            self.config['app_name'] = config['app_name']
        if 'app_id' in config:
            self.config['app_id'] = config['app_id']
        if 'app_secret' in config:
            self.config['app_secret'] = config['app_secret']
        if 'redirect_uri' in config:
            self.config['redirect_uri'] = config['redirect_uri']
        if 'scope' in config:
            self.config['scope'] = config['scope']
        if 'api_base' in config:
            self.config['api_base'] = config['api_base']
        if 'token_url' in config:
            self.config['token_url'] = config['token_url']
        if 'tenant_id' in config:
            self.config['tenant_id'] = config['tenant_id']
        if 'grant_type' in config:
            self.config['grant_type'] = config['grant_type']
        if 'verbose' in config:
            self.config['verbose'] = config['verbose']

        self.cache('read') # read cached state (if any)

        if self.token_seconds() > 5:
            self.print_msg(' -> graphhelper.AppConnect: ' + \
                'cached access token will be valid for {0} seconds'. \
                format(self.token_seconds()))
        else:
            self.print_msg(' -> graphhelper.AppConnect: cached access token has expired')
            self.get_token()

        self.after_login = '/' # redirect to home page of web app

    def cache(self, action):
        """Manage cached session state

        'save' = save current state
        'read' = restore state from cached version
        'clear' = clear cached state
        """
        cachefile = 'cache/appstate.json'

        if action == 'save':
            pass #/// see service.json, this needs changes for service settings
        elif action == 'read':
            pass #/// see service.json, this needs changes for service settings
        else:
            if os.path.isfile(cachefile):
                os.remove(cachefile)
            self.print_msg(' -> graphhelper.AppConnect: local cache cleared')

    def get_token(self):
        """Request a token from Azure AD."""

        state = '///state///'
        adminconsent_url = 'https://login.microsoftonline.com/' + self.config['tenant_id'] + \
            '/adminconsent?client_id=' + self.config['app_id'] + \
            '&state=' + state + '&redirect_uri=' + self.config['redirect_uri']
        webbrowser.open(adminconsent_url, new=1, autoraise=True)
        #/// when we accept the requested permissions, AAD redirects to the redirect_uri:
        # http://localhost:5000/?admin_consent=True&tenant=a881dde8-c7ae-423b-bb04-fcb44dc5acad&state=%2f%2f%2fstate%2f%2f%2f
        # need to stand up a handler for this, and then that handler gets the token
        return

        #/// CONTINUE MODIFICATIONS to handle Client Credentials workflow instead of Authorization Code Grant

        # Verify that this authorization attempt came from this app, by checking
        # the received state, which should match the state (uuid) sent with our
        # authorization request.
        if self.state['authstate'] != request.query.state:
            raise Exception(' -> SHUTTING DOWN: state mismatch' + \
                '\n\nState SENT: {0}\n\nState RECEIVED: {1}'. \
                format(str(self.state['authstate']), str(request.query.state)))
        self.state['authstate'] = '' # reset session state to prevent re-use

        # try to fetch an access token
        response = requests.post(self.config['token_url'], \
            data=dict(client_id=self.config['app_id'],
                      client_secret=self.config['app_secret'],
                      grant_type='authorization_code',
                      code=authcode,
                      redirect_uri=self.config['redirect_uri']))
        if self.save_token(response):
            token_response = response # valid token returned and saved
        else:
            token_response = None # token request failed

        if not token_response:
            # no response
            self.print_msg(' -> graphhelper.AppConnect: request for access token failed')
            return redirect(self.after_login)
        if not token_response.ok:
            # error response
            return token_response.text

        # set properties for current authenticated user
        me_response = self.get('me')
        me_data = me_response.json()
        if 'error' in me_data:
            self.print_msg(' -> graphhelper.AppConnect: /me endpoint returned an error ... ' + \
                str(me_data))
        self.me = me_data

        self.cache('save') # update cached session state
        return redirect(self.after_login)

    def logout(self):
        """Close current connection."""
        self.state['loggedin'] = False
        self.state['authstate'] = None
        self.state['access_token'] = None
        self.state['token_expires_at'] = 0
        self.me = dict()
        self.cache('clear')

    #/// need custom implementation here for service apps; no scopes, for example
    def save_token(self, response):
        """Save a new access token and related metadata.

        response = response object returned by self.config['token_url'] endpoint

        Returns True if the token was successfully saved, False if not.
        """
        jsondata = response.json()
        if not 'access_token' in jsondata:
            # no access token found in the response
            self.logout()
            self.print_msg(' -> graphhelper.AppConnect: request for access token failed')
            return False

        self.state['access_token'] = jsondata['access_token']
        self.state['loggedin'] = True

        self.state['token_type'] = jsondata['token_type']
        if self.state['token_type'] != 'Bearer':
            self.print_msg(' -> graphhelper.AppConnect: ' + \
                'expected Bearer token type, but received {0}'. \
                format(self.state['token_type']))

        # Verify that the scopes returned include all scopes requested. The
        # offline_access scope is never returned by Azure AD, so we don't
        # include it in scopes_expected if present.
        scopes_expected = set([_.lower() for _ in self.config['scopes']
                               if _.lower() != 'offline_access'])
        scopes_returned = \
            set([_.lower() for _ in jsondata['scope'].split(' ')])
        if scopes_expected > scopes_returned:
            self.print_msg('WARNING: expected scopes not returned = {1}'. \
                format(' '.join(scopes_expected - scopes_returned)))
        self.state['token_scope'] = jsondata['scope']

        # token_expires_at = time.time() value (seconds) at which it expires
        self.token_expires_at = time.time() + int(jsondata['expires_in'])
        self.refresh_token = jsondata.get('refresh_token', None)

        self.print_msg(' -> graphhelper.AppConnect: access token acquired ({0} bytes)'. \
            format(len(self.state['access_token'])))
        return True

class UserConnect(GraphConnection):
    """Connect to Microsoft Graph by authenticating the user and getting an
    access token from Azure Active Directory.
    """
    def __init__(self, config=None):
        """
        config = configuration settings dictionary

        If config dictionary contains a configfile entry, settings are loaded
        from that JSON file first, then other entries in the config dictionary
        may override those settings if desired.
        """

        super().__init__() # base class initialization

        if not config:
            # if no config settings provided, read default config file
            config = {'configfile': 'config/userconnect.json'}
        if 'configfile' in config:
            # merge settings from config file. Explicit settings in the config
            # object are retained (take precedence over config file entries)
            filesettings = json.loads(open(config['configfile']).read())
            for key in filesettings:
                if key not in config:
                    config[key] = filesettings[key]

        # store settings
        if 'app_name' in config:
            self.config['app_name'] = config['app_name']
        if 'app_id' in config:
            self.config['app_id'] = config['app_id']
        if 'app_secret' in config:
            self.config['app_secret'] = config['app_secret']
        if 'redirect_uri' in config:
            self.config['redirect_uri'] = config['redirect_uri']
        if 'scopes' in config:
            self.config['scopes'] = config['scopes']
        if 'api_base' in config:
            self.config['api_base'] = config['api_base']
        if 'auth_base' in config:
            self.config['auth_base'] = config['auth_base']
        if 'token_url' in config:
            self.config['token_url'] = config['token_url']
        if 'verbose' in config:
            self.config['verbose'] = config['verbose']

        self.cache('read') # read cached state (if any)

        if self.token_seconds() > 5:
            self.print_msg(' -> graphhelper.UserConnect: ' + \
                'cached access token will be valid for {0} seconds'. \
                format(self.token_seconds()))
        else:
            if self.state['access_token']:
                self.print_msg(' -> graphhelper.UserConnect: cached access token has expired')
                self.refresh_access_token()
                self.cache('save')
            else:
                self.print_msg(' -> graphhelper.UserConnect: no cached token found')

        self.after_login = '/' # redirect to home page of web app

    def authcode_abbrev(self, authcode=None):
        """Return abbreviated version of an authorization code for display
        purposes. Defaults to self.state['authcode'] if no authcode value specified.
        """
        if not authcode:
            code = self.state['authcode']
        if not code:
            return 'None'
        return code[:3] + '...' + code[-3:] + ' ({0} bytes)'.format(len(code))

    def cache(self, action):
        """Manage cached session state

        'save' = save current state
        'read' = restore state from cached version
        'clear' = clear cached state
        """
        cachefile = 'cache/userstate.json'

        if action == 'save':
            statedata = dict(auth_url=self.state['auth_url'],
                             access_token=self.state['access_token'],
                             token_expires_at=self.state['token_expires_at'],
                             token_scope=self.state['token_scope'],
                             refresh_token=self.state['refresh_token'],
                             loggedin=self.state['loggedin'])
            if not os.path.isdir('cache'):
                os.mkdir('cache')
            open(cachefile, 'w').write(json.dumps(statedata))

        elif action == 'read':
            if os.path.isfile(cachefile):
                configdata = json.loads(open(cachefile).read())
                self.state['auth_url'] = configdata['auth_url']
                self.state['access_token'] = configdata['access_token']
                self.state['token_expires_at'] = configdata['token_expires_at']
                self.state['token_scope'] = configdata['token_scope']
                self.state['refresh_token'] = configdata['refresh_token']
                self.state['loggedin'] = configdata['loggedin']
                self.update_me()
        else:
            if os.path.isfile(cachefile):
                os.remove(cachefile)
            self.print_msg(' -> graphhelper.UserConnect: logged out, local cache cleared')

    def fetch_token(self, authcode):
        """attempt to fetch an access token, using specified authorization code.
        """
        self.state['authcode'] = authcode
        response = requests.post(self.config['token_url'], \
            data=dict(client_id=self.config['app_id'],
                      client_secret=self.config['app_secret'],
                      grant_type='authorization_code',
                      code=authcode,
                      redirect_uri=self.config['redirect_uri']))

        if self.save_token(response):
            return response # valid token returned and saved
        else:
            return None # token request failed

    def get_token(self):
        """Use received authorization code to request a token from Azure AD."""

        # Verify that this authorization attempt came from this app, by checking
        # the received state, which should match the state (uuid) sent with our
        # authorization request.
        if self.state['authstate'] != request.query.state:
            raise Exception(' -> SHUTTING DOWN: state mismatch' + \
                '\n\nState SENT: {0}\n\nState RECEIVED: {1}'. \
                format(str(self.state['authstate']), str(request.query.state)))
        self.state['authstate'] = '' # reset session state to prevent re-use

        # try to fetch an access token
        token_response = self.fetch_token(request.query.code)
        if not token_response:
            # no response
            self.print_msg(' -> graphhelper.UserConnect: request for access token failed')
            return redirect(self.after_login)
        if not token_response.ok:
            # error response
            return token_response.text

        self.update_me()
        self.cache('save')

        return redirect(self.after_login)

    def login(self, redirect_to='/'):
        """Ask user to authenticate via web interface at auth_url endpoint."""
        self.state['authstate'] = str(uuid.uuid4()) # used to verify source of auth request
        self.after_login = redirect_to # where to redirect after login

        #Set the auth_url property, including required OAuth2 parameters
        self.state['auth_url'] = self.config['auth_base'] + \
            ('' if self.config['auth_base'].endswith('/') else '/') + \
            '?response_type=code&client_id=' + self.config['app_id'] + \
            '&redirect_uri=' + self.config['redirect_uri'] + \
            '&scope=' + '%20'.join(self.config['scopes']) + \
            '&state=' + self.state['authstate']

        self.print_msg(' -> graphhelper.UserConnect: asking user to authenticate')
        redirect(self.state['auth_url'], 302)

    def logout(self, redirect_to='/'):
        """Close current connection and redirect to specified route.

        If redirect_to == None, no redirection will take place and we just
        clear the current logged-in status.
        """
        self.state['loggedin'] = False
        self.me = dict()
        self.state['authstate'] = None
        self.state['access_token'] = None
        self.state['token_expires_at'] = 0
        self.cache('clear')

        if redirect_to:
            redirect(redirect_to)

    def save_token(self, response):
        """Parse a retrieved access token out of the response from the token
        endpoint, save the access token and related metadata.

        response = response object returned by self.config['token_url'] endpoint

        Returns True if the token was successfully saved, False if not.
        """
        jsondata = response.json()
        if not 'access_token' in jsondata:
            # no access token found in the response
            self.logout(redirect_to=None)
            self.print_msg(' -> graphhelper.UserConnect: request for access token failed')
            return False

        self.state['access_token'] = jsondata['access_token']
        self.state['loggedin'] = True

        self.state['token_type'] = jsondata['token_type']
        if self.state['token_type'] != 'Bearer':
            self.print_msg(' -> graphhelper.UserConnect: ' + \
                'expected Bearer token type, but received {0}'. \
                format(self.state['token_type']))

        # Verify that the scopes returned include all scopes requested. The
        # offline_access scope is never returned by Azure AD, so we don't
        # include it in scopes_expected if present.
        scopes_expected = set([_.lower() for _ in self.config['scopes']
                               if _.lower() != 'offline_access'])
        scopes_returned = \
            set([_.lower() for _ in jsondata['scope'].split(' ')])
        if scopes_expected > scopes_returned:
            self.print_msg('WARNING: expected scopes not returned = {1}'. \
                format(' '.join(scopes_expected - scopes_returned)))
        self.state['token_scope'] = jsondata['scope']

        # token_expires_at = time.time() value (seconds) at which it expires
        self.state['token_expires_at'] = time.time() + int(jsondata['expires_in'])
        self.state['refresh_token'] = jsondata.get('refresh_token', None)

        self.print_msg(' -> graphhelper.UserConnect: access token acquired ({0} bytes)'. \
            format(len(self.state['access_token'])))
        return True

    def update_me(self):
        """Populate self.me and self.photo based on current user identity."""
        me_response = self.get('me')
        me_data = me_response.json()
        if 'error' in me_data:
            self.print_msg(' -> graphhelper.UserConnect: /me endpoint returned an error ... ' + \
                str(me_data))
        self.me = me_data

        profile_pic = self.get('me/photo/$value', stream=True)
        if profile_pic.ok:
            self.photo = base64.b64encode(profile_pic.raw.read())
        else:
            self.photo = None # no profile photo available
