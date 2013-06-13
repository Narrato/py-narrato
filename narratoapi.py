#
# Copyright 2013, the py-Narrato authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Minimal Narrato API client.
"""

import cStringIO
import datetime
import hashlib
import json
import logging
import mimetools
import mimetypes
import os
import shutil
import urllib
import urllib2
import urlparse

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO


JSON_CTYPE = 'application/json'
FORM_CTYPE = 'application/x-www-form-urlencoded'
MULTIPART_CTYPE = 'multipart/form-data'
DEFAULT_CTYPE = 'application/octet-stream'


class Error(Exception):
    """Base class for any error raised by this module."""

class ApiError(Error):
    """Raised when the server reports a problem with our request."""
    def __init__(self, msg, code, meta=None):
        Error.__init__(self, msg)
        self.code = code
        self.meta = meta

class Bag(dict):
    """Simple dict subclass that exports items as attributes.
    """
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)


def json_default(o):
    if isinstance(o, datetime.datetime):
        return o.strftime('%Y-%m-%dT%H:%M:%S')
    raise TypeError('cannot JSON encode %r' % (o,))


def json_dumps(o):
    return json.dumps(o, default=json_default)


def ascii(s):
    if isinstance(s, unicode):
        return s.encode('ascii')
    return str(s)


def obj_uuid(o):
    """Given an object or string ID, return the string ID.
    """
    return str(o if isinstance(o, basestring) else o['uuid'])


class Multipart(object):
    def __init__(self):
        self.sio = cStringIO.StringIO()
        self.boundary = 2 * hashlib.md5(mimetools.choose_boundary()).hexdigest()
        self.content_type = '%s; boundary=%s' % (MULTIPART_CTYPE, self.boundary)

    def add(self, name, value):
        self.sio.write('--%s\r\n' % (self.boundary,))
        self.sio.write('Content-Disposition: form-data; name="%s"'
                       % (ascii(name),))
        self.sio.write('\r\n\r\n')
        self.sio.write(ascii(value))
        self.sio.write('\r\n')

    def add_json(self, name, dct):
        self.add_file(name, cStringIO.StringIO(json_dumps(dct)),
                      headers={'Content-type': JSON_CTYPE})

    def add_file(self, name, fp, filename=None, headers=None, public=False):
        fp_name = getattr(fp, 'name', 'unknown')
        if filename is None:
            filename = os.path.basename(fp_name)
        if headers is None:
            headers = {}
        if 'Content-type' not in headers:
            cts = mimetypes.guess_type(fp_name)[0]
            headers['Content-type'] = cts[0] if cts else DEFAULT_CTYPE

        self.sio.write('--%s\r\n' % (self.boundary,))
        self.sio.write(
            'Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
            % (ascii(name), ascii(filename)))
        for key, value in headers.iteritems():
            self.sio.write('%s: %s\r\n' % (ascii(key), ascii(value)))
        self.sio.write('\r\n')
        shutil.copyfileobj(fp, self.sio)
        self.sio.write('\r\n')

    def update(self, dct):
        for key, value in dct.iteritems():
            if hasattr(value, 'read'):
                self.add_file(key, value)
            else:
                self.add(key, value)

    def finalize(self):
        self.sio.write('--%s--\r\n\r\n' % (self.boundary,))
        return self.sio.getvalue()


class NiceRequest(urllib2.Request):
    """urllib2.Request subclass that adds support for JSON and multipart
    bodies.
    """
    def __init__(self, method, url, headers={}):
        urllib2.Request.__init__(self, url, headers=headers)
        self.get_method = lambda: method.upper()

    def set_data(self, dct, as_json=False):
        if as_json:
            self.add_unredirected_header('Content-type', JSON_CTYPE)
            self.add_data(json_dumps(dct))
        elif any(hasattr(o, 'read') for o in dct.itervalues()):
            # Requires multipart:
            mpt = Multipart()
            mpt.update(dct)
            self.add_unredirected_header('Content-type', mpt.content_type)
            self.add_data(mpt.finalize())
        else:
            self.add_unredirected_header('Content-type', FORM_CTYPE)
            self.add_data(urllib.urlencode(dct))


class Client(object):
    """Main class for interacting with Narrato's API.

        `client_id`:
            Your application's OAuth client ID. It can be found at
            https://www.narrato.co/account/apps/

        `client_secret`:
            Your application's OAuth client secret. it can be found at
            https://www.narrato.co/account/apps/

        `server_name`:
            Narrato environment to connect to.

        `ssl`:
            Use SSL for communication? Useful for development.

        `access_token`:
            Existing OAuth access token for the user account you are accessing.
            If not provided, :py:meth:direct_login or :py:meth:web_login must
            be invoked to create a session.

            After login, the access token may be persisted by reading the
            :py:attr:access_token attribute.

        `password_grant_secret`:
            If your application is authorized for password authentication, this
            is the password grant secret available from
            https://www.narrato.co/account/apps/
    """
    LOG = logging.getLogger('narratoapi.Client')

    def __init__(self, client_id, client_secret,
            server_name='www.narrato.co', ssl=True, access_token=None,
            password_grant_secret=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.server_name = server_name
        self.ssl = ssl
        #: The user's access token, or ``None`` to indicate no session.
        self.access_token = access_token
        self.password_grant_secret = password_grant_secret

        self.scheme = 'https' if ssl else 'http'
        self.base_url = '%s://%s/api/v1/' % (self.scheme, server_name)

    def _url(self, suffix, **kwargs):
        url = urlparse.urljoin(self.base_url, suffix)
        for key, value in (kwargs or {}).iteritems():
            if value is None:
                continue
            elif type(value) is bool:
                value = int(value)
            url += ('&' if '?' in url else '?')
            url += urllib.urlencode({key: value})
        return url

    def _json_resp(self, resp):
        if resp.headers['Content-type'] != JSON_CTYPE:
            raise ApiError(resp.read(), resp.code, meta=None)
        js = json.loads(resp.read(), object_pairs_hook=Bag)
        meta = js.get('meta', {})
        if not (200 <= meta.get('code', 200) < 300):
            raise ApiError('%(code)s: %(error)s' % meta, meta['code'], meta)
        return js

    def oauth_login(self, redirect_uri):
        return self._url('/oauth/authenticate', **{
            'response_type': 'token',
            'redirect_uri': redirect_uri,
            'request_code': '1234',
            'client_id': self.client_id
        })

    def direct_login(self, username, password, scope='all'):
        """Acquire a client token using OAuth login flow."""
        assert self.password_grant_secret is not None
        url = self._url('/oauth/access_token')
        js = self._json_resp(self._post(url, form={
            'grant_type': 'password',
            'username': username,
            'password': password,
            'client_id': self.client_id,
            'password_grant_secret': self.password_grant_secret,
            'scope': scope
        }, as_json=False))
        self.access_token = js['access_token']

    def _request(self, req):
        req.add_header('Accept', 'application/json')
        if self.access_token:
            req.add_unredirected_header('Authorization',
                'Bearer %s' % (self.access_token,))
            # This hack is solely so we have cutpasteable NARDEBUG output.
            if req.get_method().upper() == 'GET':
                s = vars(req)['_Request__original']
                s += '?&'['?' in s] + 'access_token=' + self.access_token
                vars(req)['_Request__original'] = s

        self.LOG.debug('%s %s', req.get_method(), req.get_full_url())
        try:
            return urllib2.urlopen(req)
        except urllib2.HTTPError, e:
            self.LOG.error('%s %r failed: %s', req.get_method(),
                           req.get_full_url(), str(e))
            # Spazzy urllib exception objects behave exactly like response
            # objects, so just return it for .getcode() etc.
            return e

    def _get(self, url):
        return self._request(NiceRequest('GET', url))

    def _delete(self, url):
        req = urllib2.Request(url)
        req.get_method = lambda: 'DELETE'
        return self._request(req)

    def _post(self, url, form=None, as_json=True):
        req = NiceRequest('POST', url)
        req.set_data(form or {}, as_json=as_json)
        return self._request(req)

    def _patch(self, url, form=None, as_json=True):
        req = NiceRequest('PATCH', url)
        req.set_data(form or {}, as_json=as_json)
        return self._request(req)

    def get_stats(self, label, include_deleted=False):
        url = self._url('labels/%s/stats' % (obj_uuid(label),),
                            include_deleted=include_deleted)
        return self._json_resp(self._get(url)).stats

    def get_item(self, item):
        url = self._url('items/%s' % (obj_uuid(item),))
        return self._json_resp(self._get(url))['item']

    def get_label_items(self, label, include_deleted=False, ann_key=None,
                        obj_type=None, before_date=None, on_date=None,
                        after_date=None, inclusive=False):
        url = self._url('labels/%s/items' % (obj_uuid(label),),
                        include_deleted=include_deleted,
                        ann_key=ann_key,
                        obj_type=obj_type,
                        before_date=before_date,
                        after_date=after_date,
                        on_date=on_date,
                        inclusive=inclusive)
        return self._json_resp(self._get(url))['items']

    def get_items(self, include_deleted=False, ann_key=None, obj_type=None,
                  before_date=None, on_date=None, after_date=None, inclusive=False):
        url = self._url('items',
                        include_deleted=include_deleted,
                        ann_key=ann_key,
                        obj_type=obj_type,
                        before_date=before_date,
                        after_date=after_date,
                        on_date=on_date,
                        inclusive=inclusive)
        return self._json_resp(self._get(url))['items']

    def _item_from_kwargs(self, item=None, annotations=None, labels=None,
            **kwargs):
        if item is None:
            item = {}
        anns = item.setdefault('annotations', [])
        for ann in annotations or ():
            anns.append(ann)
        uuids = item.setdefault('label_uuids', [])
        for label in labels or ():
            uuids.append(obj_uuid(label))
        for fld in 'type', 'created', 'uuid', 'collection_uuid':
            if fld in kwargs:
                item[fld] = kwargs[fld]
        return item

    def add_item(self, **kwargs):
        url = self._url('items')
        item = self._item_from_kwargs(**kwargs)
        self.LOG.debug('Adding item %r', item)
        resp = self._post(url, item, as_json=True)
        return self._json_resp(resp).item

    def update_item(self, item):
        url = self._url('items/%s' % (obj_uuid(item),))
        return self._json_resp(self._patch(url, item, as_json=True)).item

    def delete_item(self, item):
        url = self._url('items/%s' % (obj_uuid(item),))
        return self._json_resp(self._delete(url))['item']

    def add_file(self, filename, filetype, content=None, public=False,
                    uuid=None):
        mpt = Multipart()
        mpt.add_json('metadata', {
            'filename': filename,
            'filetype': filetype,
            'public': '1' if public else '',
            'uuid': uuid
        })
        if content:
            if isinstance(content, basestring):
                content = cStringIO.StringIO(content)
            mpt.add_file('content', content, filename=filename)

        req = NiceRequest('POST', self._url('files'))
        req.add_unredirected_header('Content-type', mpt.content_type)
        req.add_data(mpt.finalize())
        return self._json_resp(self._request(req)).file

    def _put(self, url, data, headers=None):
        req = urllib2.Request(url, data)
        req.get_method = lambda: 'PUT'
        for key, value in (headers or {}).iteritems():
            req.add_header(key, value)
        return self._request(req)

    def _put_json(self, url, js, headers=None):
        if not headers:
            headers = {}
        headers['Content-type'] = JSON_CTYPE
        return self._put(url, json_dumps(js), headers)

    def _file_data_url(self, nfile):
        return self._url('files/%s/data' % (obj_uuid(nfile),))

    def get_file_metadata(self, nfile):
        resp = self._get(self._url('files/%s' % (obj_uuid(nfile),)))
        return self._json_resp(resp)['file']

    def set_file_content(self, nfile, data):
        """Replace a file's contents with `data`, which may be bytes or a
        file-like object."""
        # TODO: make this streamy.
        if hasattr(data, 'read'):
            data = data.read()
        if not isinstance(data, bytes):
            raise ValueError('data must be bytes or file, got %r' % (data,))

        resp = self._put(self._file_data_url(nfile), data, {
            'Content-type': 'text/silly'
        })
        return self._json_resp(resp)['file']

    def get_file_content(self, nfile):
        """Return a file-like object representing the file's content."""
        return self._get(self._file_data_url(nfile))

    def delete_file(self, nfile):
        url = self._url('files/%s' % (obj_uuid(nfile),))
        resp = self._delete(url)
        return self._json_resp(resp)['file']

    def get_appdata(self):
        resp = self._get(self._url('users/me/appdata'))
        return self._json_resp(resp)['appdata']

    def set_appdata(self, data):
        resp = self._put_json(self._url('users/me/appdata'), data)
        return self._json_resp(resp)['appdata']

    def get_user(self, username='me'):
        resp = self._get(self._url('users/%s' % (username,)))
        return self._json_resp(resp)['user']

    def delete_appdata(self):
        self._delete(self._url('users/me/appdata'))
        return self._json_resp(resp)

    def create_user(self, username, email, password):
        url = self._url('/oauth/createuser')
        resp = self._post(url, {
            'username': username,
            'email': email,
            'password': password,
            'client_id': self.client_id,
        }, as_json=False)
        return self._json_resp(resp)

    def search_users(self, q):
        url = self._url('users/search', q=q)
        return self._json_resp(self._get(url))['users']

    def _label_from_kwargs(self, label=None, annotations=None, **kwargs):
        if label is None:
            label = {}
        anns = label.setdefault('annotations', [])
        for ann in annotations or ():
            anns.append(ann)
        for fld in 'app_visible', 'name', 'visible':
            if fld in kwargs:
                label[fld] = kwargs[fld]
        return label

    def get_labels(self):
        url = self._url('labels/')
        return self._json_resp(self._get(url))['labels']

    def get_label(self, label):
        url = self._url('labels/%s' % (obj_uuid(label),))
        return self._json_resp(self._get(url))['label']

    def get_label_stats(self, label):
        url = self._url('labels/%s/stats' % (obj_uuid(label),))
        return self._json_resp(self._get(url))['stats']

    def update_label(self, label):
        url = self._url('labels/%s' % (obj_uuid(label),))
        return self._json_resp(self._patch(url, label, as_json=True))['label']

    def add_label(self, **kwargs):
        url = self._url('labels/')
        label = self._label_from_kwargs(**kwargs)
        self.LOG.debug('Adding label %r', label)
        resp = self._post(url, label, as_json=True)
        return self._json_resp(resp)['label']

    def get_label_items(self, label, include_deleted=False):
        url = self._url('labels/%s/items' % (obj_uuid(label),),
                            include_deleted=include_deleted)
        return self._json_resp(self._get(url))['items']

    def unlabel_item(self, label, item):
        url = self._url('labels/%s/items/%s' %\
            (obj_uuid(label), obj_uuid(item)))
        return self._json_resp(self._delete(url))['item']

    def deleted_item_ids(self, days=None, since_version=None):
        url = self._url('items/deleted',
            days=days, since_version=since_version)
        return self._json_resp(self._get(url))['deletedids']

    def csv_export(self, cols=None, include_deleted=False):
        if isinstance(cols, list):
            cols = ','.join(cols)
        url = self._url('items/csv', cols=cols, include_deleted=False)
        return self._json_resp(self._get(url))['csv']

