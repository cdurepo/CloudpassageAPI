#########################################################
# This file is what I am submitting to do the request APIExercise
# It will provide a report of some of the top issues via the HALO SDK
# It will run either directly or in a Docker image.
# Instructions on how to do both are in the README file.
# Created by Chris Durepo 10/1/2019
#########################################################

###
# Updated by Chris Durepo on 10/2/2019
# Updated by CGD on 10/3/2019
# Updated by CGD on 10/4/2019
# Updated by CGD on 10/5/2019
# Updated by CGD on 10/6/2019


import cloudpassage
import pprint
from operator import itemgetter
import getopt, sys
import Reports

### Args to create session connectoin to cloudpassage
api_key=""
api_secret=""

## These vars could be move to a config file.
debug = 0
MAX_REPORT=10


### Command line args setup
fullCmdArguments = sys.argv
argumentList = fullCmdArguments[1:]

unixOptions = "s:k:d:h"
gnuOptions = ["secret=", "key=", "debug=", "help"]

try:
    arguments, values = getopt.getopt(argumentList, unixOptions, gnuOptions)
except getopt.error as err:
    # output error, and return with an error code
    print (str(err))
    sys.exit(2)

# evaluate given options
for currentArgument, currentValue in arguments:
    if currentArgument in ("-h", "--help"):
        print ("displaying help")
    elif currentArgument in ("-d", "--debug"):
        print (("Running with debug value (%s)") % (currentValue))
    elif currentArgument in ("-k","--key"):
        api_key=currentValue
    elif currentArgument in ("-s","--secret"):
        api_secret=currentValue

### End command line args setup

#Needed for printing during creation can be removed later if needed.
pp = pprint.PrettyPrinter(indent=4)

## Create session object for cloudpassage API
session = cloudpassage.HaloSession(api_key, api_secret)
csp = cloudpassage.CspFinding(session)
list_of_csp = csp.list_all()

print ("# Root Group: {}".format(Reports.get_root_name(session)))
print ("")
print ("")
print ("### Vulnerabilities by CSP account")
print ("")
print ("")
print ("##### Top ten CSP most-vulnerable CSP accounts, for CSP-level issues (Cloud Secure), with counts.")
print("----- | -----")
Reports.get_csp_findings(session, list_of_csp, csp)
print ()
print ()
print("##### Top ten CSP most-vulnerable CSP accounts, Server SVA issues (Server Secure), with counts.")
print("----- | -----")
Reports.get_svm_issues(session, "svm")
print ()
print ()
print("##### Top ten CSP most-vulnerable CSP accounts, Server configuration issues (Server Secure), with counts.")
print("----- | -----")
Reports.get_svm_issues(session, "sca")
print ()
print ()
print ("### Most common issues")
print()
print()
print ("##### Top ten most common CSP configuration issues: CIS ID, Descriptions with counts.")
print ("csp_rule_id | rule_name | count")
print ("---- | ---- | ----")
Reports.get_configuration_issues(session, list_of_csp)
print()
print()
print("##### Top ten most common server configuration mistakes: CIS IDs, descriptions, and counts.")
print("CIS ID (if available) description | count")
print("----- |-----")
Reports.get_server_config_issues(session)
print()
print()
print()
print("##### Top ten most common CVEs across entire account: CVE ID, CVSS score, with counts.")
print("cve_id | cvss_score | count")
print("-----|-----|-----")
Reports.get_top_cve(session)
