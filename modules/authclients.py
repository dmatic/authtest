import urllib2
from gluon.contrib.appconfig import AppConfig

myconf = AppConfig(reload=True)

facebook_key=myconf.get('authkeys.facebook_key')
facebook_secret=myconf.get('authkeys.facebook_secret')
google_key=myconf.get('authkeys.google_key')
google_secret=myconf.get('authkeys.google_secret')
linkedin_key=myconf.get('authkeys.linkedin_key')
linkedin_secret=myconf.get('authkeys.linkedin_secret')
twitter_key=myconf.get('authkeys.twitter_key')
twitter_secret=myconf.get('authkeys.twitter_secret')

## import required modules
try:
    import json
except ImportError:
    from gluon.contrib import simplejson as json
from facebook import GraphAPI, GraphAPIError
from gluon.contrib.login_methods.oauth20_account import OAuthAccount


class googleAccount(OAuthAccount):
    AUTH_URL="https://accounts.google.com/o/oauth2/auth"
    TOKEN_URL="https://accounts.google.com/o/oauth2/token"

    def __init__(self):
        OAuthAccount.__init__(self, None,
                                google_key,
                                google_secret,
                                auth_url=self.AUTH_URL,
                                token_url=self.TOKEN_URL,
    approval_prompt='force', state='auth_provider=google',
    scope='https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email')

    def get_user(self):
        token = self.accessToken()
        if not token:
            return None

        uinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo?access_token=%s' % urllib2.quote(token, safe='')
        uinfo = None
        try:
            uinfo_stream = urllib2.urlopen(uinfo_url)
        except:
            session.token = None
            return
        data = uinfo_stream.read()
        uinfo = json.loads(data)
        return dict(first_name = uinfo['given_name'],
                        last_name = uinfo['family_name'],
                        username = uinfo['id'], email=uinfo['email'])


## extend the OAUthAccount class
class FaceBookAccount(OAuthAccount):
    """OAuth impl for FaceBook"""
    AUTH_URL="https://graph.facebook.com/oauth/authorize"
    TOKEN_URL="https://graph.facebook.com/oauth/access_token"

    def __init__(self):
        OAuthAccount.__init__(self, None, facebook_key, facebook_secret,
                              self.AUTH_URL, self.TOKEN_URL,
                              scope='email,user_about_me, user_birthday, user_education_history, user_hometown, user_likes, user_location, user_relationships, user_relationship_details, user_religion_politics, user_work_history, user_photos, user_status, user_videos, publish_actions',
                              state="auth_provider=facebook",
                              display='popup')
        self.graph = None

    def get_user(self):
        '''Returns the user using the Graph API.
        '''
        if not self.accessToken():
            return None

        if not self.graph:
            self.graph = GraphAPI((self.accessToken()))

        user = None
        try:
            user = self.graph.get_object("me")
        except GraphAPIError, e:
            session.token = None
            self.graph = None

        if user:
            if not user.has_key('username'):
                username = user['id']
            else:
                username = user['username']
                
            if not user.has_key('email'):
                email = '%s.fakemail' %(user['id'])
            else:
                email = user['email']    

            print user

            return dict(first_name = user['name'],
                        last_name = user['name'],
                        username = username,
                        email = '%s' %(email) )

from gluon.http import HTTP
try:
    from linkedin.linkedin import LinkedInApplication
except ImportError:
    raise HTTP(400, "linkedin module not found")

from gluon.contrib.login_methods.oauth20_account import OAuthAccount
import hashlib
import random

LK_RETURN_URL = 'http://fw1.sshreach.me:10210/authtest/default/user/login'

class LinkedInAccount(OAuthAccount):
    TOKEN_URL="https://www.linkedin.com/uas/oauth2/accessToken"
    AUTH_URL="https://www.linkedin.com/uas/oauth2/authorization"

    def __init__(self):
        OAuthAccount.__init__(self, 'linkedin', linkedin_key, linkedin_secret,
                              self.AUTH_URL, self.TOKEN_URL,
                              scope='r_emailaddress',
                              state=self._make_new_state())

    def _make_new_state(self):
        return hashlib.md5(
            '%s%s' % (random.randrange(0, 2 ** 63), LK_SECRET)).hexdigest()

    def get_user(self):
        if not self.accessToken():
            return None
        app = LinkedInApplication(token=self.accessToken())
        profile = app.get_profile(selectors=['id', 'first-name', 'last-name', 'email-address'])
        if profile:
            if not profile.has_key('username'):
                username = profile['id']
            else:
                username = profile['username']

            if not profile.has_key('emailAddress'):
                email = '%s.fakemail' %(profile['id'])
            else:
                email = profile['emailAddress']

            return dict(first_name = profile['firstName'],
                            last_name = profile['lastName'],
                            username = username,
                            email = '%s' %(email) )            

# use the above class to build a new login form

# class TwitterAccount(OAuthAccount):
#     AUTH_URL = "https://twitter.com/oauth/authorize"
#     TOKEN_URL = "https://twitter.com/oauth/request_token"
#     ACCESS_TOKEN_URL = "https://twitter.com/oauth/access_token"

#     def __init__(self, g):
#         OAuthAccount.__init__(self, g, twitter_key, twitter_secret, self.AUTH_URL, self.TOKEN_URL, self.ACCESS_TOKEN_URL)

#     def get_user(self):
#         if self.accessToken() is not None:
#             consumer = Consumer(key=self.CLIENT_ID, secret=self.CLIENT_SECRET)
#             client = Client(consumer, self.accessToken())
#             resp, content = client.request('http://api.twitter.com/1/account/verify_credentials.json')
#             if resp['status'] != '200':
#                 # cannot get user info. should check status
#                 #redirect("http://google.com")
#                 return None
#             u = json.loads(content)
#             return dict(first_name = u['name'], username=u['screen_name'], name=u['name'], registration_id=u['id'])
# auth.settings.login_form=TwitterAccount(g=globals())
