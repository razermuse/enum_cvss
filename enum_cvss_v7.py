#!/usr/bin/env python3

import requests
import json
import csv
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys
import argparse
import re
import time
from datetime import datetime
from pprint import pprint

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
    Find CVSS 2.x and CVSS 3.x base scores for a given component.

Explanation:
    Pull component data via a list; if there are vulnerabilities: display CVSS 2 and CVSS 3 basescores.

Errors are logged to 'enum_cvss.log'.

Positional arguments:
    -s       --save      <filename> (optional)

Optional arguments:
    Common Options:
    -h        --help     Display this help message.
    -i        --info     Display base URL, authentication URL, API/Bearer/CSRF Tokens, and commands selected.
    -q        --quiet    Quiet mode.
    -s        --save     Save results. Will use 'enum_output.csv' if a filename isn't given.
    -vv       --verbose  Display (or save) vulnerability name, severity, description, HREF, and affected projects.
    -v        --version  Version of this program.

Examples:
    python3 enum_cvss.py
'''% sys.argv[0]

def init_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Enumerate vulnerable components', add_help=False, usage=get_usage())
    parser.add_argument('-h', '--help', help='This help file.')
    parser.add_argument('-i', '--info', help='Display base URL, authentication URL, API Token, Bearer Token, CSRF Token, and commands selected', action='store_true')
    parser.add_argument('-q', '--quiet', help='Quiet mode', action='store_true')
    parser.add_argument('-s', '--save', help='Save results to an outfile. If a filename isn\'t given \'enum_output.csv\'', action='store_true')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 7.0', help='Version.')
    parser.add_argument('-vv', '--verbose', help='Display more data about the components', action='store_true')
    return parser

# Global variables
BASEURL="https://poc09.blackduck.synopsys.com"
AUTHURL="%s/api/tokens/authenticate" % (BASEURL)
WAIT=30
api_token="NDc1NGNkNDEtZThlNS00YzZlLTkwZGMtOTU3N2YxN2NiZDk1OmQxMzY4MDVkLTNiZjctNGFlNC04MWI5LTU3YzIwNjc3M2ZiYw=="
today_date = datetime.now()
date_time = today_date.strftime('%Y-%m-%d %H:%M')
f=open("component.csv")
f_log="enum_cvss.log"
http_method="GET"
payload = {}
project_name = {}
project_version_name = {}
output = {
    'logs' : []
}

def log(entry):
    '''
    Append new log entries for errors
    '''
    output['logs'].append(entry)

    with open(f_log, "w") as outfile:
        json.dump(output, outfile, indent=4)

def save(entry):
    '''
    Append new entries to save file
    '''

    output['logs'].append(entry)

    if arg_save:
        f_output="enum_output.csv"
    else:
        f_output = arg_save

    with open(f_output, "w") as outfile:
        json.dump(output, outfile, indent=4)

        if (not arg_quiet):
            print(f"\033[0;37;40m" + "Appending output to: " + f_output)

def http_error_check(url, headers, code, response):
    '''
    Function to check the HTTP status code.
    '''
    if (code == 200):
        return

    if (code >  399):
        print(f"\nWe were unable to pull info from this endpoint.\n")
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
      'Content-Type':'application/json',
      'Authorization':'token '+ api_token
    }

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    response = requests.request("POST", url, headers=headers, data=payload, verify=False, timeout=30)
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
    response = requests.request(http_method, url, headers=headers, data=payload, verify=False)
    code = response.status_code
    http_error_check(url, headers, code, response)

    if (code == 200):
        result=json.loads(response.text)
    elif (code > 500):
        print(f"\n\033[0;37;40m" + "CloudFlare 5xx error.")

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
        # To display last X of instead of the full variable: bearerToken[len(bearerToken) - X:]
        print(f"\033[0;37;40m" + "Bearer Token: " + "\033[0;33;40m" + bearerToken)
        print(f"\033[0;37;40m" + "CSRF Token: " + "\033[0;33;40m" + csrfToken)
        print(f"\n\033[0;37;40m" + "Commands selected: " + "\033[0;33;40m" + str(args))

    return

def get_components_from_list():
    '''
    Function to enumerate a comma separated list of components and verions.
    '''
    for row in csv.reader(f):

        try:
            component = row[0]
        except:
            continue

        get_component(component)

        print(f"\n\033[7m" + "\033[1;33m" + "Waiting... " + str(WAIT) + " seconds to space out our queries.")
        time.sleep(WAIT)

    return

def get_component(component):
    '''
    Function to enumerate component ID and component version. Only pulls vulnerabilities if vulns > 0.
    '''
    url = '%s/api/search/components-in-use?limit=100&offset=0&q=%s' % (BASEURL, component)
    headers = {
       'Accept':'application/vnd.blackducksoftware.internal-1+json',
       'Authorization':'bearer '+bearerToken,
       'X-CSRF-TOKEN':csrfToken
    }
    results = get_url(http_method, url, headers, payload)

    for comps in results['items']:

        component_name = comps['componentName']
        component_id = comps['_meta']['href'].split('/')[5]
        critical = comps['riskProfile']['categories']['VULNERABILITY']['CRITICAL']
        high = comps['riskProfile']['categories']['VULNERABILITY']['HIGH']
        medium = comps['riskProfile']['categories']['VULNERABILITY']['MEDIUM']
        low = comps['riskProfile']['categories']['VULNERABILITY']['LOW']
        ok = comps['riskProfile']['categories']['VULNERABILITY']['OK']
        unknown = comps['riskProfile']['categories']['VULNERABILITY']['UNKNOWN']
        try:
            component_version = comps['componentVersion']
        except:
            continue

        if (critical or high or medium or low or ok or unknown > 0):

            if (not arg_quiet):
                print(f"\n\033[0;37;40m" + "Component Name: " + "\033[0;33;40m" + component_name + "\033[0;37;40m" + "  Component Version: " + "\033[0;33;40m" + component_version + "\033[0;37;40m" + "  Component ID: " + "\033[0;33;40m" + component_id)

                if critical > 0:
                    print(f"\033[0;37;40m" + "Critical: " + "\033[0;31;40m" + str(critical))
                if high > 0:
                    print(f"\033[0;37;40m" + "High: " + "\033[0;31;40m" + str(high))
                if medium > 0:
                    print(f"\033[0;37;40m" + "Medium: " + "\033[0;31;40m" + str(medium))
                if low > 0:
                    print(f"\033[0;37;40m" + "Low: " + "\033[0;31;40m" + str(low))
                if ok > 0:
                    print(f"\033[0;37;40m" + "Ok: " + "\033[0;31;40m" + str(ok))
                if unknown > 0:
                    print(f"\033[0;37;40m" + "Unknown: " + "\033[0;31;40m" + str(unknown))

            get_vulnerabilities(component_name, component_version, component_id)
    return

def get_vulnerabilities(component_name, component_version, component_id):
    '''
    Function to enumerate vulnerable components from a list of components.
    '''
    url = '%s/api/components/%s/vulnerabilities' % (BASEURL, component_id)
    headers = {
       'Accept':'application/vnd.blackducksoftware.vulnerability-4+json',
       'Authorization':'bearer '+bearerToken,
       'X-CSRF-TOKEN':csrfToken
    }
    results = get_url(http_method, url, headers, payload)

    for vulns in results['items']:
        try:
            href = vulns['_meta']['href']
            cvss2_basescore = str(vulns['cvss2']['baseScore'])
            cvss3_basescore = str(vulns['cvss3']['baseScore'])
            description = vulns['description']
            name = vulns['name']
            severity = vulns['severity']

        except KeyError:
            continue

        if (not arg_quiet) and (not arg_verbose):
            print(f"\033[0;37;40m" + "CVSS 2 Basescore: " + "\033[0;31;40m" + cvss2_basescore + " " + "\033[0;37;40m" + "CVSS 3 Basescore: " + "\033[0;31;40m" + cvss3_basescore + "\n")

            if arg_save:
                save (f"{component_name}, {name}, {component_id}, {cvss2_basescore}, {cvss3_basescore}")

        if (not arg_quiet) and (arg_verbose):
            print(f"\n\033[0;37;40m" + "Checking for vulnerabilities... ")
            print(f"\033[0;37;40m" + "Vulnerability Name: " + "\033[0;31;40m" + name + "\033[0;37;40m" + " (Severity: " + "\033[0;31;40m" + severity + "\033[0;37;40m" + ")")
            print(f"\033[0;37;40m" + "Description: " + "\033[0;36;40m" + description)
            print(f"\033[0;37;40m" + "CVSS 2 Basescore: " + "\033[0;31;40m" + cvss2_basescore + " " + "\033[0;37;40m" + "CVSS 3 Basescore: " + "\033[0;31;40m" + cvss3_basescore)
            print(f"\033[0;37;40m" + "HREF: " + "\033[0;37;40m" + href)

            get_affected(component_name, name, component_id, cvss2_basescore, cvss3_basescore)

    return

def get_affected(component_name, name, component_id, cvss2_basescore, cvss3_basescore):
    '''
    Function to enumerate affected projects.
    '''
    url = '%s/api/vulnerabilities/%s/affected-projects' % (BASEURL, name)
    headers = {
       'Accept':'application/vnd.blackducksoftware.vulnerability-4+json',
       'Authorization':'bearer '+bearerToken,
       'X-CSRF-TOKEN':csrfToken
    }
    results = get_url(http_method, url, headers, payload)

    if results['items'] == []:
        if (not arg_quiet) and arg_verbose:
            print(f"\033[0;37;40m" + "Affected Projects: " + "\033[0;33;40m" + " no projects or versions found")

    for vulns in results['items']:
        try:
            project_name = vulns['projectName']
            project_version_name = vulns['projectVersionName']

            if (not arg_quiet) and arg_verbose:
                print(f"\033[0;37;40m" + "Affected Projects: " + "\033[0;33;40m" + project_name + " (" + project_version_name + ")")
                if arg_save:
                    save (f"{component_name}, {name}, {component_id}, {cvss2_basescore}, {cvss3_basescore}, {project_name}, {project_version_name}")

        except:
            continue

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
        get_components_from_list()

    except KeyboardInterrupt:
        print(f"\033[0;33;40m" + "\n[Control-C detected]\n")
        sys.exit()
