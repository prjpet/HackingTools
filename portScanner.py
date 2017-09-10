#!/usr/bin/python

import optparse
from socket import *
from threading import *

screenLock = Semaphore(value=1)

def connScan(tgtHost, tgtPort):
	#In order to grab the application banner from our target host, we must first
	#insert additional code into the connScan function. After discovering an open
	#port, we send a string of data to the port and wait for the response. Gathering
	#this response might give us an indication of the application running on the
	#target host and port.
	
	
	try:
		connSkt = socket(AF_INET, SOCK_STREAM)
		connSkt.connect((tgtHost, tgtPort))
		connSkt.send('ViolentPython\r\n')
		results = connSkt.recv(100)
		screenLock.acquire()
		print '[+]%d/tcp open'% tgtPort
		print '[+] ' + str(results)
	except:
		screenLock.acquire()
		print '[-]%d/tcp closed'% tgtPort
	finally:
		screenLock.release()
		connSkt.close()
		
def portScan(tgtHost, tgtPorts):
	try:
		tgtIP = gethostbyname(tgtHost)
	except:
		print "[-] Cannot resolve '%s': Unknown host"%tgtHost
		return
	try:
		tgtName = gethostbyaddr(tgtIP)
		print '\n[+] Scan Results for: ' + tgtName[0]
	except:
		print '\n[+] Scan Results for: ' + tgtIP
		
	setdefaulttimeout(1)
	for tgtPort in tgtPorts:
		t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
		t.start()
		#print 'Scanning port ' + tgtPort
		#connScan(tgtHost, int(tgtPort))



def Main():
    #In our first step, we accept the hostname and port from the user. For this, our
    #program utilizes the optparse library for parsing command-line options. The
    #call to optparse. OptionPaser([usage message]) creates an instance of an option
    #parser. Next, parser.add_option specifies the individual command line options
    #for our script. The following example shows a quick method for parsing the
    #target hostname and port to scan.
	
    parser = optparse.OptionParser('usage %prog -H <target host> -p <target port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help='specify target port[s] separated by comma')

    (options, args) = parser.parse_args()

    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(',')
 
    if (tgtHost == None) | (tgtPorts[0] == None):
        print parser.usage
        exit(0)
	
    portScan(tgtHost, tgtPorts)
	
if __name__ == "__main__":
	Main()