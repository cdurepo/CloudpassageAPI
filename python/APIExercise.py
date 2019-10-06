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


def get_root_name(session):
    ### Get root group Name for report using the SDK
    # assume that if the parent is none it is the root group
    groups = cloudpassage.ServerGroup(session)
    list_of_groups = groups.list_all()
    rootGroupName = ""
    for s in list_of_groups:
        if debug > 2: print("ID: {} Name: {} Parent: {}".format(s["id"], s["name"], s["parent_id"]))
        if(s["parent_id"] == None):
            rootGroupName = s["name"]

    return rootGroupName
### Get get_root_name

def get_csp_findings(session, list_of_csp):
    ## Get list of CSP findings so we can work through them to rank accounts by the number issues.
    ### Start CSP Findings
    # Top 4 most vulnerable accounts

    csp_level_issues={}
    for s in list_of_csp:
        csp_info = cloudpassage.CspFinding(session)
        csp_id_info = csp.list_all(rule_id=[s["rule_id"]])
        for i in csp_id_info:
            if i["csp_account_id"] in csp_level_issues:
                csp_level_issues[i["csp_account_id"]]+=1
            else:
                csp_level_issues[i["csp_account_id"]]=1
    csp_level_issues_sorted = sorted(csp_level_issues.items(), key =
                 lambda kv:(kv[1], kv[0]), reverse=True)
    # Make sure our output is not less than the limit or we will have index errors.
    limit = MAX_REPORT
    if len(csp_level_issues_sorted) < 10:
        limit = len(csp_level_issues_sorted)
    for i in range(0, limit):
        print (csp_level_issues_sorted[i][0]," |",csp_level_issues_sorted[i][1])
### End get_csp_findings

def get_svm_issues(session, server_issue_type):
    ## Top 4 CSP accounts by SVA/SVM issues on Server
    # Get all the servers issues for each server, get the SVM
    # count then update the output dict with the lastes numbers
    #
    # dict for the csp level issues output
    csp_level_issues ={}

    # Get server info from API
    serverList = cloudpassage.Server(session)
    list_of_servers = serverList.list_all()
    # process list of servers and look for issues_sorted
    for s in list_of_servers:
        #pp.pprint(s)
        issues = serverList.issues(s["id"])
        if server_issue_type in issues:
            critical_count = 0
            non_critical_count = 0
            if debug > 2 :print("CSP Account ID: {} ID: {} Critical Count: {} Non critical count: {}".format(s["csp_account_id"], issues["id"], issues["svm"]["critical_findings_count"], issues["svm"]["non_critical_findings_count"]))
            if s["csp_account_id"] in csp_level_issues:
                critical_count = csp_level_issues[s["csp_account_id"]]["critical_findings_count"]
                non_critical_count = csp_level_issues[s["csp_account_id"]]["non_critical_findings_count"]

            dict_update = {
            "critical_findings_count":issues["svm"]["critical_findings_count"]+critical_count,
            "non_critical_findings_count":issues["svm"]["non_critical_findings_count"]+non_critical_count}
            csp_level_issues[s["csp_account_id"]]=dict_update
    #Add the critical and non critical.  I am keeping them seperate for now, I would like them to be shown that way but that was not the request.
    csp_level_issues_temp = {}
    for i in csp_level_issues:
        csp_level_issues_temp[i]=csp_level_issues[i]["critical_findings_count"]+csp_level_issues[i]["non_critical_findings_count"]
    csp_level_issues_sorted = sorted(csp_level_issues_temp.items(), key =
                 lambda kv:(kv[1], kv[0]), reverse=True)
    # Make sure our output is not less than the limit or we will have index errors.
    limit = MAX_REPORT
    if len(csp_level_issues_sorted) < 10:
        limit = len(csp_level_issues_sorted)
    for i in range(0, limit):
        print (csp_level_issues_sorted[i][0]," |",csp_level_issues_sorted[i][1])
### end get_svm_issues

def get_configuration_issues(session, list_of_csp):
    #  Top ten most common CSP configuration issues: Descriptions with counts.

    top_configuration_issues={}
    for s in list_of_csp:
        name_id = "%s|%s" % (s["csp_rule_id"],s["rule_name"])
        top_configuration_issues[name_id]=s["fail"]

    issues_sorted=sorted(top_configuration_issues.items(), key =
                 lambda kv:(kv[1], kv[0]), reverse=True)
    for i in range(0, 10):
        print (issues_sorted[i][0]," |", issues_sorted[i][1] )
### End get_configuration_issues

def get_server_config_issues(session):
    # Top ten most common server configuration mistakes: CIS IDs, descriptions, and
    #counts.
    # Get the list of all the CSP issues by server limited to "csm" then count, and order the output.

    top_server_issues={}
    csp_issues = cloudpassage.Issue(session)
    list_of_issues = csp_issues.list_all(issue_type=["csm"])
    for s in list_of_issues:
        name_id = "%s" % (s["name"])
        if name_id in top_server_issues.keys() :
            top_server_issues[name_id]+=1
        else:
            top_server_issues[name_id]=1
    top_server_issues_sorted=sorted(top_server_issues.items(), key =
                 lambda kv:(kv[1], kv[0]), reverse=True)
    for i in range(0, 10):
        print (top_server_issues_sorted[i][0]," |",top_server_issues_sorted[i][1])
## Issues: not all the entries have a cis_id at the front of the name, some of the name have a carriage return
### End get_server_config_issues


def get_top_cve(session):
    # Top ten most common CVEs across entire account: CVE ID, CVSS score, with
    # counts.
    # Need to go through each issues, get all the CVEs (there might be a list) and count them all as we go.
    # then we need to look up the score for the CVEs once we have them
    top_cve_issues={}
    csp_issues = cloudpassage.Issue(session)
    list_of_issues= csp_issues.list_all()
    for s in list_of_issues:
        list_of_cves_from_issues={}
        if "cves" in s.keys():
            list_of_cves_from_issues=s["cves"]
            #pp.pprint(list_of_cves_from_issues)
            for l in list_of_cves_from_issues:
                if l in top_cve_issues.keys():
                    top_cve_issues[l]+=1
                else:
                    top_cve_issues[l]=0
    top_cve_issues_sorted=sorted(top_cve_issues.items(), key =
                 lambda kv:(kv[1], kv[0]), reverse=True)
    cve=cloudpassage.CveDetails(session)

    for i in range(0, 10):
        print(top_cve_issues_sorted[i][0], " |",cve.describe(top_cve_issues_sorted[i][0])["CVSS Metrics"]["score"]," |", top_cve_issues_sorted[i][1])

### End get_top_cve

## Create session object for cloudpassage API
session = cloudpassage.HaloSession(api_key, api_secret)

csp = cloudpassage.CspFinding(session)
list_of_csp = csp.list_all()
#pp.pprint(list_of_csp)
#exit()
print ("# Root Group: {}".format(get_root_name(session)))
print ("")
print ("")
print ("### Vulnerabilities by CSP account")
print ("")
print ("")
print ("##### Top ten CSP most-vulnerable CSP accounts, for CSP-level issues (Cloud Secure), with counts.")
print("----- | -----")
get_csp_findings(session, list_of_csp)
print ()
print ()
print("##### Top ten CSP most-vulnerable CSP accounts, Server SVA issues (Server Secure), with counts.")
print("----- | -----")
get_svm_issues(session, "svm")
print ()
print ()
print("##### Top ten CSP most-vulnerable CSP accounts, Server configuration issues (Server Secure), with counts.")
print("----- | -----")
get_svm_issues(session, "sca")
print ()
print ()
print ("### Most common issues")
print()
print()
print ("##### Top ten most common CSP configuration issues: CIS ID, Descriptions with counts.")
print ("csp_rule_id | rule_name | count")
print ("---- | ---- | ----")
get_configuration_issues(session, list_of_csp)
print()
print()
print("##### Top ten most common server configuration mistakes: CIS IDs, descriptions, and counts.")
print("CIS ID (if available) description | count")
print("----- |-----")
get_server_config_issues(session)
print()
print()
print()
print("##### Top ten most common CVEs across entire account: CVE ID, CVSS score, with counts.")
print("cve_id | cvss_score | count")
print("-----|-----|-----")
get_top_cve(session)
