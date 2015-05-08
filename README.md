# NFqueue SIP hijacker

Simple "proxy" application to demonstrate NFQUEUE usage
- register iptables rules that push SIP messages to proxy
- proxy modifies called phone numbers of outgoing INVITE messages
- undoes phone number substitution of incoming SIP messages
- fakes SIP message digest authentication (password of UA must be known)
