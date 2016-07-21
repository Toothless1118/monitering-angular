#stdlib
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
	username = instance.get('username')
	password = instance.get('password')

	if not url:
	    raise Exception("Bad configuration. You must specify a url")
	return url, login_url, username, password

    def _get_gzip_status_with_cookie(self, url, cookies):
	gzip_status = 0
	try:
    	    getres = requests.get(url, cookies=cookies)
	    for key in getres.headers:
		if key == "content-encoding":
		    encode_status = getres.headers['content-encoding']
    		    if encode_status == "gzip":
    	    		gzip_status = 1
	except socket.timeout, e:
	    self.log.info("%s is Down, error: %s. Connection failed" % (url, str(e)))

	except requests.exceptions.ConnectionError, e:
	    self.log.info("%s is Down, error: %s. Connection failed" % (url, str(e)))

	except socket.error, e:
	    self.log.info("%s is Down, error: %s. Connection failed" % (url, str(e)))

	except Exception, e:
	    self.log.error("Unhandled exception %s, Connection failed" % (str(e)))
	    raise

	return gzip_status

    def _get_gzip_status_without_cookie(self, url):
	gzip_status = 0
	try:
    	    getres = requests.get(url)
	    for key in getres.headers:
		if key == "content-encoding":
		    encode_status = getres.headers['content-encoding']
    		    if encode_status == "gzip":
    	    		gzip_status = 1
	except socket.timeout, e:
	    self.log.info("%s is Down, error: %s. Connection failed" % (url, str(e)))

	except requests.exceptions.ConnectionError, e:
	    self.log.info("%s is Down, error: %s. Connection failed" % (url, str(e)))

	except socket.error, e:
	    self.log.info("%s is Down, error: %s. Connection failed" % (url, str(e)))

	except Exception, e:
	    self.log.error("Unhandled exception %s, Connection failed" % (str(e)))
	    raise

	return gzip_status


    def check(self, instance):
	addr, login_url, username, password = self._load_conf(instance)
	gzip_status = 0
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
		    gzip_status = self._get_gzip_status_with_cookie(addr, cval)
	    except socket.timeout, e:
		self.log.info("%s is Down, error: %s. Connection failed" % (addr, str(e)))

	    except requests.exceptions.ConnectionError, e:
		self.log.info("%s is Down, error: %s. Connection failed" % (addr, str(e)))

	    except socket.error, e:
		self.log.info("%s is Down, error: %s. Connection failed" % (addr, str(e)))

    	    except Exception, e:
		self.log.error("Unhandled exception %s, Connection failed" % (str(e)))
		raise

	else:
	    gzip_status = self._get_gzip_status_without_cookie(addr)

	tags_list = []
	tags_list.append('url:%s' %addr)

	self.gauge('http.gzip_check', gzip_status, tags=tags_list)
