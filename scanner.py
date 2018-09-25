import os, sys, argparse
import json
import linecache
from urlparse import urlparse
import requests
import time
from datetime import date

apipath = "https://api.ssllabs.com/api/v2/"

infocommand = apipath + "info"
analyzecommand = apipath + "analyze"
getdatacommand = apipath + "getEndpointData"

# clean up domain
def parsetodomain(url):
	if "http" not in url:
		url = "http://" + url
	pdomain = ''
	parsed_uri = urlparse(url)
	pdomain = '{uri.netloc}'.format(uri=parsed_uri)
	return (pdomain)

mainapps = []
get_cache=False
date = str(date.today())

# create command line arguments
# invoke program: python scanner.py -i domains.txt (-o)
# optional -o for cached results
parser = argparse.ArgumentParser(description='SSL Scanner')
parser.add_argument('-i','--input', help='The input file with list of URLs', required=True)
parser.add_argument('-o','--cache', help='Accept cached results (if available)', action='store_true')
args = parser.parse_args()

in_file = str(args.input)
get_cache = bool(args.cache)

# create folder in cwd for results
if not os.path.exists(os.getcwd() + "/ssllabs_" + date):
    os.makedirs(os.getcwd() + "/ssllabs_" + date, 0777)

line_no = 1
read_line = linecache.getline(in_file, line_no).rstrip()

while read_line is not "":
	line_no = line_no + 1
	mainapps.append(read_line)
	read_line = linecache.getline(in_file, line_no).rstrip()
	
total_lines = line_no - 1

print "\nThere are %d Urls read from the File" % (total_lines)


# set parameters for new and cached results 
if get_cache == False:
	pstart = {"publish" : "off", "ignoreMismatch" : "on", "all" : "done", "host" : "", "startNew" : "on"}
else:
	pstart = {"publish" : "off", "ignoreMismatch" : "on", "all" : "done", "host" : "", "fromCache" : "on", "maxAge" : 72}
prerepeat = {"publish" : "off", "ignoreMismatch" : "on", "all" : "done", "host" : ""}

def analyze(pdomain):
	print('Initializing scan for ' + pdomain)
	pstart['host'] = pdomain
	prerepeat['host'] = pdomain

	# request api with set parameters
	results = requests.get(analyzecommand, params=pstart)
	status_code = results.status_code
	results.raise_for_status()
	data = results.json()

	# trigger requests until scan is complete
	while data['status'] != 'READY' and data['status'] != 'ERROR':
		print(pdomain + " scan is in progress, please wait for the results.")
		print("Sleeping for 1 min...")
		time.sleep(60)
		results = requests.get(analyzecommand, params=prerepeat)
		data = results.json()
		results.raise_for_status()

		if data['status'] == 'READY':
			print(pdomain + ' scan is complete!\n')

	# display a summary of the results for host and associated endpoints
	endpoints = data['endpoints']
	for endpoint in endpoints:
		if 'ipAddress' in endpoint.keys():

			# in case server names are not given 
			if 'serverName' in endpoint.keys():
				serverName = endpoint['serverName']
			else:
				serverName = '-'

			# in case grades are not given
			if 'grade' in endpoint.keys():
				grade = endpoint['grade']
				certExp = time.ctime(int(endpoint['details']['cert']['notAfter']/1000))
				certIs = endpoint['details']['cert']['issuerLabel']
			else:
				grade = '-'
				certExp = '-'
				certIs = '-'

			# in case of errors from server
		print('----------------------------------------------')

		if endpoint['statusMessage'] == "Ready":
			print('Assessment completed!')
		else:	
			statusm = endpoint['statusMessage']
			print('Assessment failure: ' + statusm)

		print "Host: %s:%s:%s\nServer Name: %s\nIP Address: %s\nGrade: %s\nCertIssuer: %s\nCertExpiration: %s\n" % (
			data['protocol'],
			data['host'],
			data['port'],
			serverName,
			endpoint['ipAddress'],
			grade,
			certIs,
			certExp
		)

		print('----------------------------------------------')

		print('\nFull details can be found in the results folder created in your current working directory.\n')
	
	return(data)

# create files containing json results for each domain
for app in mainapps:
	pdomain = parsetodomain(app)
	output = analyze(pdomain)
	file=open("ssllabs_" + date + "/" + pdomain + ".txt", 'w')
	file.write(json.dumps(output, indent=2, sort_keys=True))
