#!/usr/bin/env python3

import requests
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys
import argparse
import re
from datetime import datetime
#from pprint import pprint

def get_usage():
    """Returns the usage information for this tool.
    """

    return'''


#
#
#     _____ ____  _   _ ____          ____ _   _ ___  ___
#    | ___ |  _ \| | | |    \        / ___) | | /___)/___)
#    | ____| | | | |_| | | | |______( (___ \ V /___ |___ |
#    |_____)_| |_|____/|_|_|_(_______)____) \_/(___/(___/
#
#
#


%s
    Find cvss2 and cvss3 base scores for a given component.

Explanation:
    This script pulls component data via a list from the BD API and if there are vulnerabilities, will display the CVSS 2.x and CVSS 3.x base scores. Errors are logged to enum_cvss.log.

Positional arguments:
    At the moment - none but it does require a list of component names to iterate through.

Optional arguments:
    Common Options:
    -h        --help    Print this help message
    -i        --info    Print authentication information in addition to CVSS data
    -q        --quiet   Quiet mode
    -s        --save    Save output to 'enum_output.csv'
    -v        --version Version of this program
    -vv       --verbose Verbosity of output

Examples:
    python3 enum_cvss.py
'''% sys.argv[0]

def init_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Enumerate vulnerable components', add_help=False, usage=get_usage())
    parser.add_argument('-h', '--help', help='This help file.')
    parser.add_argument('-i', '--info', help='Display authentication information', action='store_true')
    parser.add_argument('-q', '--quiet', help='Quiet mode', action='store_true')
    parser.add_argument('-s', '--save', help='Display authentication information', action='store_true')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 5.0', help='Version.')
    parser.add_argument('-vv', '--verbose', help='Display more data about the components', action='store_true')
    return parser

# Global variables
BASEURL="https://poc09.blackduck.synopsys.com"
AUTHURL="%s/api/tokens/authenticate" % (BASEURL)
api_token="NDc1NGNkNDEtZThlNS00YzZlLTkwZGMtOTU3N2YxN2NiZDk1OmQxMzY4MDVkLTNiZjctNGFlNC04MWI5LTU3YzIwNjc3M2ZiYw=="
today_date = datetime.now()
date_time = today_date.strftime('%Y-%m-%d %H:%M')
http_method="GET"
payload = {}
output = {
    'logs' : []
}

def log(entry):
    '''
    Append new log entries
    '''
    
    output['logs'].append(entry)

    if arg_save:
        filename = "enum_output.csv"
    else:
        filename = "enum_cvss.log"

    if (not arg_quiet) and arg_save:
        print(f"\033[0;37;40m" + "Appending output to: " + filename)

    with open(filename, "w") as outfile:
        json.dump(output, outfile, indent=4)

def http_error_check(url, headers, code, response):
    '''
    Function to check the HTTP status code.
    '''

    if (code == 200):
        return

    if (code >  399):
        print(f"We were unable to pull info from this endpoint.\n")
        log (f"{date_time} URL: {url} HEADERS: {headers} HTTP error: {code}")
        log (response.text)
        sys.exit()

    else:
        raise Exception("Error while getting data.", code)

    return

def get_auth(): 
    '''
    Function to authenticate to the BD API and grab the bearer token and csrf token.
    '''
    url = AUTHURL
    headers = {
      'Accept':'application/vnd.blackducksoftware.user-4+json',
      'Authorization':'token '+api_token
    }

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    response = requests.request("POST", url, headers=headers, data=payload, verify=False, timeout=5)
    code = response.status_code
    http_error_check(url, headers, code, response)

    if (code == 200):
        global bearerToken, csrfToken
        bearerToken = response.json()['bearerToken']
        csrfToken = response.headers['X-CSRF-TOKEN']

    return

def get_url(http_method, url, headers, payload):
    '''
    Function to enumerate data from a URL or API endpoint.
    '''

    # Authentication requires a POST, all other endpoints use a GET
    response = requests.request(http_method, url, headers=headers, data=payload, verify=False, timeout=5)
    code = response.status_code
    http_error_check(url, headers, code, response)

    if (code == 200):
        result=json.loads(response.text)

    return result 

def user_info():
    '''
    Function to display initial information to the user.
    '''

    if arg_quiet:
        print(f"\n\033[0;37;40m" + "Quiet mode is [ENABLED]")
    else:
        print(f"\n\033[0;37;40m" + "Quiet mode is [DISABLED]")
    
    if arg_info and (not arg_quiet):
        print(f"\n\033[0;37;40m" + "Attempting authentication to: " + "\033[0;34;40m" + AUTHURL)
        print(f"\033[0;37;40m" + "API Token: " + "\033[0;33;40m" + api_token)
        print(f"\033[0;37;40m" + "Bearer Token: " + "\033[0;33;40m" + bearerToken)        
        print(f"\033[0;37;40m" + "CSRF Token: " + "\033[0;33;40m" + csrfToken)
        # To display last X of instead of the full variable: bearerToken[len(bearerToken) - X:]

    return

def get_components():
    '''
    Function to enumerate a list of components.
    '''    
    count = 0
    with open('component.txt', 'r') as file:
        for line in file:
            count += 1
            component_name = line.strip()
        
            if (not arg_quiet):
                print(f"\n\033[0;37;40m" + "Component name: " + "\033[0;33;40m" + component_name)
                get_vulnerabilities(component_name)
    return

def get_vulnerabilities(component_name):
    '''
    Function to enumerate vulnerable components from a list of components.
    '''

    url = '%s/api/search/vulnerabilities?limit=100&offset=0&q=%s' % (BASEURL, component_name) 
    headers = {
       'Accept':'application/vnd.blackducksoftware.internal-1+json',
       'Authorization':'bearer '+bearerToken,
       'X-CSRF-TOKEN':csrfToken
    }
    results = get_url(http_method, url, headers, payload)

    if (len(results['items']) == 0):
        print("\033[0;37;40m" + "Vulnerability ID: " + "\033[0;31;40m" + "This component does not have vulnerabilities at this time.")
        vuln_id = "00000"
        summary = "There is no vulnerability associated with " + component_name + "."
        cvss2 = "0"
        cvss3 = "0"

        if arg_save:
            log (f"{component_name}, {vuln_id}, {cvss2}, {cvss3}")

    for vulns in results['items']:
        try:
            href = vulns['_meta']['href']
            vuln_id = vulns['vulnerabilityId']
            cwe_id = str(vulns['cweIds'])
            summary = vulns['summary']
            affected_projs = vulns['_meta']['links']
        except KeyError:
            print("Key Error in: " + url)
            continue

        if (not arg_quiet) and (not arg_verbose):
            print(f"\n\033[0;37;40m" + "Checking for vulnerabilities... ")
            
            if vuln_id:
                print("\033[0;37;40m" + "Vulnerability ID: " + "\033[0;31;40m" + vuln_id)
                try:
                    get_cvss(component_name, vuln_id)
                except KeyError:
                    # For when there is no CVSS 2 or CVSS 3 score
                    continue

        if (not arg_quiet) and arg_verbose:
            print(f"\n\033[0;37;40m" + "Pulling from: " + "\033[0;34;40m" + url)
            print(f"\n\033[0;37;40m" + "Checking for vulnerabilities... ")

            if (vuln_id):
                print("\033[0;37;40m" + "Vulnerability ID: " + "\033[0;31;40m" + vuln_id)
                print("\033[0;37;40m" + "Summary: " + "\033[0;33;40m" + summary)
                    
                marker1 = '\''
                marker2 = '\''
                regexPattern = marker1 + '(.+?)' + marker2
                try:
                    # Most cases, CWE_ID needs this group(1) part to parse the CWE ID
                    str_found = re.search(regexPattern, cwe_id).group(1)
                except AttributeError:
                    # In some cases, group(1) throws an error and needs to have group(1) removed
                    str_found = re.search(regexPattern, cwe_id)
                print("\033[0;37;40m" + "CWE ID: " + "\033[0;31;40m" + str(str_found))

                try:
                    get_cvss(component_name, vuln_id)
                except KeyError:
                    # For when there is no CVSS 2 or CVSS 3 score
                    continue

                for affected in affected_projs:
                    rel = affected['rel']
                    href = affected['href']

                    if (rel == 'affected-projects'):
                        print(f"\033[0;37;40m" + "Affected Projects: " + "\033[0;34;40m" + href + "\n")
    
    return

def get_cvss(component_name, vuln_id):
    '''
    Function to enumerate CVSS 2 and CVSS 3 scores using vuln_id.
    '''
    
    url = '%s/api/vulnerabilities/%s' % (BASEURL, vuln_id)
    headers = {
       'Accept':'application/vnd.blackducksoftware.vulnerability-4+json',
       'Authorization':'bearer '+bearerToken,
       'X-CSRF-TOKEN':csrfToken
    }
    results = get_url(http_method, url, headers, payload)

    cvss2 = str(results['cvss2']['baseScore'])
    cvss3 = str(results['cvss3']['baseScore'])
    
    if (not arg_quiet):
        print(f"\033[0;37;40m" + "CVSS 2 Base Score: " + "\033[0;37;40m" + cvss2)
        print(f"\033[0;37;40m" + "CVSS 3 Base Score: " + "\033[0;37;40m" + cvss3)

    if arg_save:
        log (f"{component_name}, {vuln_id}, {cvss2}, {cvss3}")

    return

def main():
    '''
    Main function
    '''

    return    

# Launch program
if __name__ == '__main__':
    try:
        parser = init_argparse()
        args = parser.parse_args()
        arg_quiet = args.quiet
        arg_info = args.info
        arg_save = args.save
        arg_verbose = args.verbose
    
        get_auth()
        user_info()
        get_components()
    except KeyboardInterrupt:
        print(f"\033[0;37;40m" + "\n[Control-C detected]\n")
        sys.exit()
