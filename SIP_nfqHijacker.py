#!/usr/bin/python

# Simple "proxy" application to demonstrate NFQUEUE usage
# - register iptables rules that push SIP messages to proxy
# - proxy modifies called phone numbers of outgoing INVITE messages
# - undoes phone number substitution of incoming SIP messages
# - fakes SIP message digest authentication (password of UA must be known)

import nfqueue	as nf
from scapy.all import *
import os
from simpleSipDissector import *

# iptables rules; OUT pc -> sipserver; IN pc <- sipserver

insertOUT = "iptables -A OUTPUT -j NFQUEUE --queue-num 1 -p udp --dport 5060"
insertIN = "iptables -A INPUT -j NFQUEUE --queue-num 1 -p udp --dport 5060"
flush = "iptables -F; iptables -X;"

myIP = "a.b.c.d" #need to differentiate between incoming / outgoing
password = "abcdefgh" #needed to compute message digest authentication response
alwaysCall = "0123456789" #the number we always call

# callback that handles messages hijacked by nf
def callback(i, payload):
	global username, uri, realm, nonce, newResponse, calledNumber

	data = payload.get_data()
	pkt = IP(data)

	srcIP = pkt[IP].src

	#Incoming or outgoing?
	if (myIP == srcIP):
		print ">>>>>>>>>>>>>>>>>>>>>>>> OUTGOING >>>>>>>>>>>>>>>>>>>>>>>>"
		print "---ORIGINAL SIP MESSAGE---"
		print pkt[UDP].payload

		msg = str(pkt[UDP].payload)
		if (("INVITE" in msg) and ("response" in msg)):

			# extract message digest authentication responst calculated by UA
			oldResponse = getResponse(msg)
			print "Old Response:", oldResponse

			# replace old response with new response
			pkt[UDP].payload = str(pkt[UDP].payload).replace(oldResponse, newResponse)

		if ("INVITE" in msg):
			# extract the number UA is actually calling
			calledNumber=getCalledNumber(msg)
			print "Called Number", calledNumber

		# substitute called number by another number
		pkt[UDP].payload = str(pkt[UDP].payload).replace(calledNumber, alwaysCall)

		print "---MODIFIED SIP MESSAGE---"
		print pkt[UDP].payload
		print "=========================================================="


	else:
		print "<<<<<<<<<<<<<<<<<<<<<<<< INCOMING <<<<<<<<<<<<<<<<<<<<<<<<<"
		print "---ORIGINAL SIP MESSAGE---"
		print pkt[UDP].payload

		msg = str(pkt[UDP].payload)
		if ("SIP/2.0 407 Proxy Authentication Required" in msg):

			#extract nonce and other data needed to compute SIP message digest authentication response
			username = getUsername(msg)
			print "Username:", username

			nonce = getNonce(msg)
			print "Nonce:", nonce

			realm = getRealm(msg)
			print "Realm:", realm

			uri = getURI(msg)
			print "URI:", uri

			# calculate the SIP message digest response
			newResponse = createResponse(username, realm, password, uri, nonce)
			print "New response:", newResponse

		# undo substitution of phone numbers
		pkt[UDP].payload = str(pkt[UDP].payload).replace(alwaysCall, calledNumber)

		print "---MODIFIED SIP MESSAGE---"
		print pkt[UDP].payload
		print "=========================================================="


	# enforce computation of header checksums by scapy
	del pkt[IP].chksum
	del pkt[UDP].chksum

	# send modified message
	payload.set_verdict_modified(nf.NF_ACCEPT, str(pkt), len(pkt))


if __name__ == "__main__":

	# some newlines to better find the start of console output...
	for i in range (1,10):
		print "\n"

	# prepare one nfqueue...
	q = nf.queue()
	q.open()
	q.bind(socket.AF_INET)
	q.set_callback(callback)
	q.create_queue(1)

	try:
		# ... for multiple filter rules
		os.system(insertOUT)
		os.system(insertIN)

		# here we go!
		q.try_run()

	except KeyboardInterrupt:
		print "exiting"
		q.unbind(socket.AF_INET)
		q.close()

		# flush those nasty rules
		os.system(flush)
