import datetime

from google.cloud import ndb

class AuthToken(ndb.Model):
    """Representation of a stored authid"""
    user_id = ndb.StringProperty(required=True)
    blob = ndb.TextProperty(required=True)
    expires = ndb.DateTimeProperty(required=True, tzinfo=datetime.timezone.utc)
    service = ndb.StringProperty(required=True)


class FetchToken(ndb.Model):
    """Representation of a stored fetch token"""
    authid = ndb.StringProperty(required=False)
    token = ndb.StringProperty(required=True)
    expires = ndb.DateTimeProperty(required=True, tzinfo=datetime.timezone.utc)
    fetched = ndb.BooleanProperty(required=True)


class StateToken(ndb.Model):
    """Representation of a stored state token"""
    service = ndb.StringProperty(required=True)
    expires = ndb.DateTimeProperty(required=True, tzinfo=datetime.timezone.utc)
    fetchtoken = ndb.StringProperty(required=False)
    version = ndb.IntegerProperty(required=False)


@ndb.transactional(xg=True)
def create_fetch_token(fetchtoken):
    # A fetch token stays active for 30 minutes
    if fetchtoken is not None and fetchtoken != '':
        e = FetchToken.get_by_id(fetchtoken)
        if e is None:
            FetchToken(id=fetchtoken, token=fetchtoken, fetched=False,
                       expires=datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).put()


@ndb.transactional(xg=True)
def update_fetch_token(fetchtoken, authid):
    if fetchtoken is not None and fetchtoken != '':
        e = FetchToken.get_by_id(fetchtoken)
        if e is not None:
            e.expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=30)
            e.authid = authid
            e.fetched = False
            e.put()


@ndb.transactional()
def insert_new_authtoken(keyid, user_id, blob, expires, service):
    entry = AuthToken.get_by_id(keyid)
    if entry is None:
        entry = AuthToken(id=keyid, user_id=user_id, blob=blob, expires=expires, service=service)
        entry.put()
        return entry
    else:
        return None


@ndb.transactional(xg=True)
def insert_new_statetoken(token, service, fetchtoken, version):
    entry = StateToken.get_by_id(token)
    if entry is None:
        tokenversion = None
        try:
            tokenversion = int(version)
        except:
            pass

        entry = StateToken(
            id=token,
            service=service,
            fetchtoken=fetchtoken,
            expires=datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
            version=tokenversion)

        entry.put()
        return entry
    else:
        return None