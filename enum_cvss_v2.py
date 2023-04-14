#!/usr/bin/env python3

import csv
import requests
import json
from pprint import pprint
import pandas as pd
from pandas import DataFrame
import time
import subprocess
from subprocess import Popen, PIPE, STDOUT, call
import sys
from datetime import datetime
import argparse

# Workflow: enumerate projects to get project ID, use project ID to get versions, get components per version, enumerate vulns for each version?
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


%s {component name}
    Find cvss2 and cvss3 base scores for a given component.

Explanation:
    This script pulls component data from the BD API and if there are vulnerabilities, will display the CVSS 2.x and CVSS 3.x base scores. 

Positional arguments:
    At the moment - none. 

Optional arguments:
    Common Options:
    -h        --help    Print this help message
    -n        --name    Name of the web app
    -q        --quiet   Quiet mode
    -v        --version Version of this program

Examples:
    python3 enum_cvss.py 
'''% sys.argv[0]

# Parse command line arguments
def init_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Register app using Contrast app name', add_help=False, usage=get_usage())
    parser.add_argument('-n', '--name', help='Name of the app to register with Contrast CLI.')
    parser.add_argument('-h', '--help', help='This help file.')
    parser.add_argument('-q', '--quiet', help='Quiet mode', action='store_true')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 2.0', help='Version.')
    return parser

# Launch program
if __name__ == '__main__':
    parser = init_argparse()
    args = parser.parse_args()
    arg_quiet = args.quiet

# Global variables
authorization = "token [REDACTED]"
host = "https://poc09.blackduck.synopsys.com"
url_auth = host + "/api/tokens/authenticate"
url_projects = host + "/api/projects"
url_components = host + "/api/components?q=id:"
component = "maven%7Corg.apache.logging.log4j%7Clog4j-core%7C2.4.1"
#component = "maven%7Cspringboot"
url_ciu = host + "/api/search/components-in-use?limit=100&offset=0&q=log4j"
final_data = pd.DataFrame()
now = datetime.now()

# Start information displayed to user
if arg_quiet:
    print()
    print("\033[0;37;40m" + "Quiet mode is [ENABLED].")

if not arg_quiet:
    print()
    print("\033[0;37;40m" + "Quiet mode is [DISABLED].")
    print()
    print("\033[0;37;40m" + "Black Duck auth URL: " + "\033[0;34;40m" + url_auth)
    print()
    print("\033[0;37;40m" + "Component name: " + "\033[0;33;40m" + component)
    print()
    print("\033[0;37;40m" + "Pulling from: " + "\033[0;34;40m" + url_components + component + "/vulnerabilities")
    print()

# Authentication headers (-H flag not necessary with requests library).
headers = {
    'Accept':"application/json",
    'Authorization': authorization
}

# Submit URL and Headers to API.
auth = requests.request("POST", url_auth, headers=headers)

# Test to see if we're authenticated and if so, proceed.
if(200 == auth.status_code):

    # Enumerate App API response and store it in a variable.
    results = auth.json()

    # Loop through results from the json dictionary.
    for (value, key) in results.items():

        if value == "bearerToken":

            # Store results of the applications section.
            bearerToken = "Bearer " + key

            # Iterate through items and assigned variables.
            headers = {
                    'Accept':"application/json",
                    'Authorization': bearerToken
                    }

            # Pull data from endpoint.
            data = requests.request("GET", url_components+component, headers=headers) 
            
            # Test to see if we successfully hit the endpoint, and if so, proceed.
            if(200 == data.status_code):
  
                # Enumerate App API response and store it in a variable.
                proj_results = data.json()
                all_projects = proj_results['items']

                # Loop through results from the json dictionary.
                for projects in all_projects:   
                    component_name = projects['component']
                   
                    # Pull vulnerability data using the component's name.
                    vulnerabilities_url = component_name + "/vulnerabilities"
                    vulnerabilities_comps = requests.request("GET", vulnerabilities_url, headers=headers)

                    # Test to see if we successfully hit the endpoint, and if so, proceed. 
                    if(200 == vulnerabilities_comps.status_code):

                        # Enumerate App API response and store it in a variable.
                        comp_results = vulnerabilities_comps.json()
                        all_comp_results = comp_results['items']
                        
                        # Loop through the results from the json dictionary.
                        for comp in all_comp_results:
                            name = comp['name']
                            cvss2 = comp['cvss2']['baseScore']
                            cvss3 = comp['cvss3']['baseScore']

                            if not arg_quiet:
                                print(("\033[0;37;40m" + "Vulnerability: " + "\033[0;31;40m" + name) + "\033[0;37;40m (cvss2 base score: " + "\033[1;32;40m" + str(cvss2) + "\033[0;37;40m" + ")" + "\033[0;37;40m (cvss3 base score: " + "\033[1;32;40m" + str(cvss3) + "\033[0;37;40m" + ")")

                    # Test to see if we're not authenticated
                    elif(401 == vulnerabilities_comps.status_code):
                        if not arg_quiet:
                            print("API Returned" +str(vulnerabilities_comps.status_code) + ". Sorry, we are not authenticated to the API.")

            # Test to see if we're not authenticated
            elif(401 == data.status_code):
                if not arg_quiet:
                    print("API Returned: " + str(data.status_code) + ". Sorry, we are not authenticated to the API.")

# Test to see if we're not authenticated.
elif(401 == auth.status_code):
    if not arg_quiet:
        print("API Returned: " + str(auth.status_code) + ". Sorry, we are not authenticated to the API.")

# Test to see if we have the right page.
elif(404 == auth.status_code):
    if not arg_quiet:
        print("API Returned: " + str(auth.status_code) + ". Sorry, we couldn't find the page.")
