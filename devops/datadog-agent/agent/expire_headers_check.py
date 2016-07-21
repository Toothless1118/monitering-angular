#stdlib
import re
from datetime import datetime
import socket

#3rd party
import requests

#project
from checks.network_checks import NetworkCheck, Status, EventType

class GZIPCheck(NetworkCheck):
    def __init__(self, name, init_config, agentConfig, instances):
	NetworkCheck.__init__(self, name, init_config, agentConfig, instances)

    def _load_conf(self, instance):
	url = instance.get('url')
	login_url = instance.get('login_url')
	asset_suburls = instance.get('asset_suburls')
	username = instance.get('username')
	password = instance.get('password')

	if not url:
	    raise Exception("Bad configuration. You must specify a url")
	return url, login_url, asset_suburls, username, password
    
    def _get_expires_status_with_cookie(self, url, cookies):
	expires_status = 0
	cache_header = ""
	try:
	    res = requests.get(url, cookies=cookies)
	
	    for key in res.headers:
		if key == "cache-control":
		    cache_header = res.headers['cache-control']
	    if cache_header is not None:
		age_match = re.search(r'max-age=(\S+)', cache_header)
		if age_match is not None:
		    max_age = age_match.group(1)
		    if max_age > 0:
			expires_status = 1
		else:
		    expires_status = self._get_expires_status_from_expires(res.headers)
	    else:
		expires_status = self._get_expires_status_from_expires(res.headers)
	except socket.timeout, e:
	    self.log.info("%s is Down, error: %s. Connection failed" % (url, str(e)))

	except requests.exceptions.ConnectionError, e:
	    self.log.info("%s is Down, error: %s. Connection failed" % (url, str(e)))

	except socket.error, e:
	    self.log.info("%s is Down, error: %s. Connection failed" % (url, str(e)))

	except Exception, e:
	    self.log.error("Unhandled exception %s, Connection failed" % (str(e)))
	    raise

	return expires_status

    def _get_expires_status_without_cookie(self, url):
	expires_status = 0
	cache_header = ""
	try:
	    res = requests.get(url)
	
	    for key in res.headers:
		if key == "cache-control":
		    cache_header = res.headers['cache-control']
	    if cache_header is not None:
		age_match = re.search(r'max-age=(\S+)', cache_header)
		if age_match is not None:
		    max_age = age_match.group(1)
		    if max_age > 0:
			expires_status = 1
		else:
		    expires_status = self._get_expires_status_from_expires(res.headers)
	    else:
		expires_status = self._get_expires_status_from_expires(res.headers)
	except socket.timeout, e:
	    self.log.info("%s is Down, error: %s. Connection failed" % (url, str(e)))

	except requests.exceptions.ConnectionError, e:
	    self.log.info("%s is Down, error: %s. Connection failed" % (url, str(e)))

	except socket.error, e:
	    self.log.info("%s is Down, error: %s. Connection failed" % (url, str(e)))

	except Exception, e:
	    self.log.error("Unhandled exception %s, Connection failed" % (str(e)))
	    raise

	return expires_status


    def _get_expires_status_from_expires(self, header):
	expires_status = 0
	for key in header:
	    if key == "expires":
		expires_header = header["expires"]
		exp_date = datetime.strptime(expires_header, "%a, %d %b %Y %H:%M:%S %Z")
		days_left = exp_date - datetime.utcnow()
		if days_left.days > 0:
		    expires_status = 1
	return expires_status

    def check(self, instance):
	addr, login_url, asset_suburls, username, password = self._load_conf(instance)
	
	expires_status = 0	

	if login_url is not None:
	    try:
		auth = None
		if username is not None and password is not None:
		    auth = {'email':username, 'password':password}

		reqsession = requests.session()
		postres = reqsession.post(login_url, auth)
	
		auth_status = postres.status_code
    		if str(auth_status) == "200":
    		    cval = postres.cookies
		    
		    asset_list = asset_suburls.split(",")
		    for asset_item in asset_list:
			asset_url = addr + asset_item
			item_status = self._get_expires_status_with_cookie(asset_url, cval)
			expires_status = expires_status + item_status
		    
		else:
		    self.log.info("authentication failed")
		    expires_status = 0
	    except socket.timeout, e:
		self.log.info("%s is Down, error: %s. Connection failed" % (login_url, str(e)))

	    except requests.exceptions.ConnectionError, e:
		self.log.info("%s is Down, error: %s. Connection failed" % (login_url, str(e)))

	    except socket.error, e:
		self.log.info("%s is Down, error: %s. Connection failed" % (login_url, str(e)))

	    except Exception, e:
		self.log.error("Unhandled exception %s, Connection failed" % (str(e)))
		raise

	else:
	    asset_list = asset_suburls.split(",")
	    for asset_item in asset_list:
		asset_url = addr + asset_item
		item_status = self._get_expires_status_without_cookie(asset_url)
		expires_status = expires_status + item_status

	tags_list = []
	tags_list.append('url:%s' %addr)

	self.gauge('http.expires_header_check', expires_status, tags=tags_list)
