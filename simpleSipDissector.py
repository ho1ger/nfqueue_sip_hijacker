#!/usr/bin/python

import md5, re

# computes SIP message digest authentication response
# c.f. https://tools.ietf.org/html/draft-smith-sipping-auth-examples-01
def createResponse(username, realm, password, uri, nonce):
	A1 = username + ":" + realm + ":" + password
	m = md5.new()
	m.update(A1)
	HA1 =  m.hexdigest()

	A2 = "INVITE:" + uri
	m = md5.new()
	m.update(A2)
	HA2 = m.hexdigest()

	res = HA1 + ":" + nonce + ":" + HA2
	m = md5.new()
	m.update(res)
	res = m.hexdigest()

	return res


# Pretty ugly parser functions that retrieve
# - Username of calling UA
# - URI of called UA
# - Phone number of called UA (subset of URI)
# - Nonce from server
# - Own realm
# - message digest authentication response computed by calling UA
# No guarantee that this is complete/correct

def getUsername(msg):
	reg="From: [a-zA-Z0-9:@<>=,\". ]*"
	p = re.compile(reg)
	int = p.findall(msg)[0]

	reg=":[a-zA-Z0-9]*@"
	p = re.compile(reg)
	int = p.findall(int)[0]

	res = int.replace(":", "")
	res = res.replace("@", "")

	return res

def getURI(msg):
	reg="To: [a-zA-Z0-9:@<>=,\". ]*"
	p = re.compile(reg)
	int = p.findall(msg)[0]

	reg="<sip:[a-zA-Z0-9.]*@[a-zA-Z0-9.]*>"
	p = re.compile(reg)
	int = p.findall(int)[0]

	res = int.replace("<", "")
	res = res.replace(">", "")

	return res

def getCalledNumber(msg):
	reg="To: [a-zA-Z0-9:@<>=,\". ]*"
	p = re.compile(reg)
	int = p.findall(msg)[0]

	reg=":[a-zA-Z0-9]*@"
	p = re.compile(reg)
	int = p.findall(int)[0]

	res = int.replace(":", "")
	res = res.replace("@", "")

	return res

def getNonce(msg):
	reg="Proxy-Authenticate: [a-zA-Z0-9:@<>=,\"./+ ]*"
	p = re.compile(reg)
	int = p.findall(msg)[0]

	reg="nonce=\"[a-zA-Z0-9/+]*\""
	p = re.compile(reg)
	int = p.findall(int)[0]

	res = int.replace("nonce=\"", "")
	res = res.replace("\"", "")

	return res

def getRealm(msg):
	reg="Proxy-Authenticate: [a-zA-Z0-9:@<>=,\"./+ ]*"
	p = re.compile(reg)
	int = p.findall(msg)[0]

	reg="realm=\"[a-zA-Z0-9.]*\""
	p = re.compile(reg)
	int = p.findall(int)[0]

	res = int.replace("realm=\"", "")
	res = res.replace("\"", "")

	return res

def getResponse(msg):

	reg="Proxy-Authorization: [a-zA-Z0-9:@<>=,\"./+ ]*"
	p = re.compile(reg)
	int = p.findall(msg)[0]

	reg="response=\"[a-zA-Z0-9]*\""
	p = re.compile(reg)
	int = p.findall(int)[0]

	res = int.replace("response=\"", "")
	res = res.replace("\"", "")

	return res
