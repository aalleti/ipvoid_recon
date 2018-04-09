#!/usr/bin/python
###############################################################################################
#
# Retreive IPVoid results
# Input is an IP Address or input file containing IPs.
#
###############################################################################################
import os, sys, getopt, time, requests, re, cfg
requests.packages.urllib3.disable_warnings()

###############################################################################################
#
#  Usage/Help screen. Enough said.
#
###############################################################################################
def usage():

	print ('Usage: ',sys.argv[0],' -i <inputfile-or-IP>')
	print ('')
	print ('  Query IPVoid for reputational information on a given IP address or file containing')
	print ('  multiple IP Addresses.')
	sys.exit()

###############################################################################################
#
# Use requests to query IPVoid and use BeautifulSoup for HTML parsing.
# Returns the results for customized reporting.
#
###############################################################################################
def query( ip, proxy ):

	black=0
	result = ""
	url = "http://www.ipvoid.com/scan"

	if proxy:
		r = requests.get('%s/%s/' % (url, ip), proxies=cfg.proxies, verify=False)
	else:
		r = requests.get('%s/%s/' % (url, ip), verify=False)
	results = r.text

	if ( len(results) < 1 ):
		time.sleep(15)
		return "Failed on " + ip.rstrip()

	soup = BeautifulSoup(results)
	if soup.find(text=re.compile("Report not found")):
		return "Report not found"
	for tr in soup.find_all('table')[0].find_all('tr'):
		tds = tr.find_all('td')
		if tds[0].text == "Reverse DNS":
			result += 'Reverse DNS - ' + str(tds[1].text) + "\n"
		if tds[0].text == "ASN":
			result += 'ASN - ' + str(tds[1].text) + "\n"
		if tds[0].text == "ASN Owner":
			result += 'ASN Description - ' + str(tds[1].text) + "\n"
		if tds[0].text == "Blacklist Status":
			result += 'Status - ' + str(tds[1].span.text) + "\n"
			if "BLACKLISTED" in tds[1].span.text:
				black=1
	if black:
		result += "###" + " " * 18 + "IP Blacklist Report" + " " * 18 + "###" + "\n"
		for tr in soup.find_all('table')[1].find_all('tr')[1:]:
			tds = tr.find_all('td')
			if tds[1].find('img')['title'] == "Detected":
				result += str(tds[0].text) + ' - ' + tds[1].find('a')['href'] + '\n'

	return result

###############################################################################################
#
#  Reporting
#  Clean reporting. Prints report to STDOUT.
#
###############################################################################################
def report(ip):

	results = query(ip, proxy)
	m = re.search("Report not found", results)
	if m is not None:
		print( "-"*35 + "\nReport not found for " + ip + "\n" + "-"*35 + "\n\n")
	else:
		print ("-"*35 + "\nReport for " + ip + "\n" + "-"*35 + "\n" + results)

###############################################################################################
#
#  Main Loop
#  Performs OS detection for proxy and getopts
#  Loops over single IP Address or input file and calls report(ip) query
#
###############################################################################################
def main(argv):

	global proxy

	input=''

	# test os and set proxy appropriately
	ostype = os.uname()[0]
	if ostype == 'Linux':
		proxy = 1
	elif ostype == 'Darwin':
		proxy = 0
	else:
		report("What Operating System is this ?!?")
		proxy = 0

	try:
		opts, args = getopt.getopt(argv,"hi:",["input="])
	except getopt.GetoptError:
		usage()
	for opt, arg in opts:
		if opt == '-h':
			usage()
		elif opt in ("-i"):
			input = arg

	if (input == ""):
		usage()

	# Populate IP list
	if os.path.isfile(input):
		ips = open(input)
	else:
		ips = [ input ]

	#############################################################
	# Loop through IP list and perform a query on each IP.
	# The completed list ensures that duplicate IPs are
	# not queried. Print results if IPVoid returns a response,
	# even if the response is zero results.
	#############################################################
	completed=[]
	for ip in ips:
		if ( len(ip) == 0 ): continue
		if ip not in completed:
			completed.append(ip)
			report(ip.rstrip('\n'))
			time.sleep(10)
			#query("37.143.15.116", proxy)

if __name__ == "__main__":
	sys.path.append( os.path.dirname( os.path.dirname( os.path.abspath(__file__) ) ) )
	from bs4 import BeautifulSoup

	proxy=0
	main(sys.argv[1:])

else:
	from bs4 import BeautifulSoup
#################

