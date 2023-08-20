#! /usr/bin/env python
# -*- coding: utf-8


import os
import sys
import base64
import urllib3
import argparse
import logging
import json
import re

DEFAULT_ARG_DEBUG = False
DEFAULT_ARG_LAST  = 1

DEFAULT_SERVER           = ''
DEFAULT_LOGIN            = ''
DEFAULT_PASSWORD         = ''
DEFAULT_HEADERS          = {"Content-Type":"application/json", "Accept":"application/json", "User-Agent": "Python script", "How-Many": 100}
DEFAULT_PLAN             = 'current'
DEFAULT_JOBS_QUERY       = {"filters": {}}

CENTREON_EXIT_CRITICAL = 2
CENTREON_EXIT_WARNING  = 1
CENTREON_EXIT_OK       = 0
CENTREON_EXIT_UNKNOWN  = 3

# To disable certificate verification, value is CERT_NONE
# You can use --insecure option to set to CERT_NONE
URLLIB_OPTION_CERT_REQ = "CERT_REQUIRED"

urllib3.disable_warnings()
logging.basicConfig(level=logging.WARNING, format='%(asctime)s [%(levelname)s]: %(message)s')

def load_envfile():
    """
        Loads the values from the .env file located next to the script
        Content of file : (Do not quote value)
            SCHEDULER_PASSWORD=<value>
    """
    global DEFAULT_PASSWORD

    envFilename = '{0}/.iws_env'.format(os.path.abspath(os.path.dirname(__file__)))
    if not os.path.exists(envFilename):
        return False
    try:
        with open(envFilename, 'rt') as datafile:
            for line in datafile.readlines():
                if line != '':
                    lineKV = line.split('=')
                    if lineKV[0] == 'SCHEDULER_SERVER':
                        DEFAULT_SERVER = lineKV[1].strip()
                    elif lineKV[0] == 'SCHEDULER_LOGIN':
                        DEFAULT_LOGIN = lineKV[1].strip()
                    elif lineKV[0] == 'SCHEDULER_PASSWORD':
                        DEFAULT_PASSWORD = lineKV[1].strip()
                    elif lineKV[0] == 'SCHEDULER_PLAN':
                        DEFAULT_PLAN = lineKV[1].strip()
    except:
        logging.exception('Error when reading the .env environment file. Action ignored!')
    return True

def getRequest(requestEndpoint, requestHeaders):
    """
        Performs an HTTP GET request and returns the contents of the request in JSON format or the value None.
    """
    try:
        http = urllib3.PoolManager(cert_reqs = URLLIB_OPTION_CERT_REQ)

        response = http.request('GET', requestEndpoint, headers=requestHeaders)

        if response.status == 401:
            logging.error('The request was unsuccessful: 401 Unauthorized.')
            return None
        elif response.status != 200:
            logging.error('The request was unsuccessful: 401 Unauthorized.\nResponse : {0}'.format(response.data.decode('utf8')))
            return None
        return json.loads(response.data.decode('utf8'))
    except:
        logging.exception('Error when send the HTTP request.')
    return None

def postRequest(requestEndpoint, requestHeaders, requestData):
    """
        Performs an HTTP POST request with requestData JSON and returns the contents of the request in JSON format or the value None.
    """
    try:
        http = urllib3.PoolManager(cert_reqs = URLLIB_OPTION_CERT_REQ)

        requestBody = json.dumps(requestData).encode('utf-8')
        response = http.request('POST', requestEndpoint, headers=requestHeaders, body=requestBody)

        if response.status == 401:
            logging.error('The request was unsuccessful: 401 Unauthorized.')
            return None
        elif response.status != 200:
            logging.error('The request was unsuccessful: 401 Unauthorized.\nResponse : {0}'.format(response.data.decode('utf8')))
            return None
        return json.loads(response.data.decode('utf8'))
    except urllib3.exceptions as e:
        logging.exception('Error when send the HTTP request.')
    return None


def getWorkstationList(schedulerEndpoint, schedulerHeader, workstationQuery):
    """
        Function querying IWS to retrieve the workstation list based on a query.
    """
    workstationList = postRequest('{0}/workstation/query'.format(schedulerEndpoint), schedulerHeader, workstationQuery)
    if workstationList == None:
        logging.error('Workstation list get request failed : {0}'.format(workstationList))
        return None
    return workstationList
		
if __name__ == '__main__':
    load_envfile()

    parser = argparse.ArgumentParser(description='Script to interact with the IWS scheduler API to retrieve and print the log of job(s).')

    parser.add_argument('--server', type=str, default=DEFAULT_SERVER,
                        help='The address of the IWS scheduler server to query.')
    parser.add_argument('--login', type=str, default=DEFAULT_LOGIN,
                        help='The login username.')
    parser.add_argument('--password', type=str, default=DEFAULT_PASSWORD,
                        help='The user\'s password.')

    parser.add_argument('--plan', type=str, default=DEFAULT_PLAN,
                        help='The identifier of the plane where the search is to be made. By default, the value is {0}. The format of the identifier is YYYYMMJJHHMM (ex: 202205030500)'.format(DEFAULT_PLAN))
    parser.add_argument('-w', '--workstation', type=str,
                        help='Overload the name of the workstation where to look for the jobstream (regex is allowed, ex: "*" or "VAD*"). By default, the search is done on all the workstations.')
    parser.add_argument('-n', '--nodename', type=str,
                        help="Alternatively to the workstation name, search according to the node name (i.e. the host name). This option is not set if --workstation is used")

    parser.add_argument('-q', '--query', type=str, default=DEFAULT_JOBS_QUERY,
                        help='Advanced option to query the IWS API directly. See: https://start.wa.ibmserviceengage.com/twsd/#/%5BPlan%5D%20Job/queryJobInPlan to know the various options of query. The other selection options of the query always override this option.')
    parser.add_argument('--last', type=int, default=DEFAULT_ARG_LAST,
                        help='Allows you to specify the maximum number of jobs returned by the filter. By default, only one value is returned.')

    parser.add_argument('--insecure', action='store_true',
                        help="Bypasses verification of the HTTP request server certificate used by the urllib3 library.")
    parser.add_argument('--debug', action='store_true', default=DEFAULT_ARG_DEBUG,
                        help='This option displays the debug logs, which are much more verbose.')
    parser.add_argument('--silent', action='store_true',
                        help='This option allows you to disable all script logs. Only the information returned by the script is displayed on stdout. Recommended option for batch processing.')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().level = logging.DEBUG
    if args.silent:
        logging.getLogger().desable = True

    logging.debug(args)

    if args.insecure:
        logging.debug("Insecure mode enabled for all HTTP requests.")
        URLLIB_OPTION_CERT_REQ = "CERT_NONE"

    if args.server == '':
        print("UNKNOWN: Missing scheduler server. Please provide --server with non empty value or ensure local .env file is filled.")
        sys.exit(CENTREON_EXIT_UNKNOWN)

    if args.login == '':
        print("UNKNOWN: Missing scheduler login. Please provide --login with non empty value or ensure local .env file is filled.")
        sys.exit(CENTREON_EXIT_UNKNOWN)

    if args.password == '':
        print("UNKNOWN: Missing scheduler password. Please provide --password with non empty value or ensure local .env file is filled.")
        sys.exit(CENTREON_EXIT_UNKNOWN)

    if (args.workstation == None or args.workstation == '') and (args.nodename == None or args.nodename == ''):
        print("UNKNOWN: Missing workstation parameter. Please provide --workstation parameter.")
        sys.exit(CENTREON_EXIT_UNKNOWN)

    schedulerEndpoint = '{0}/twsd/plan/{1}'.format(args.server, args.plan)
    schedulerHeaders = DEFAULT_HEADERS
    schedulerHeaders['Authorization'] = 'Basic {0}'.format(base64.encodestring('{0}:{1}'.format(args.login, args.password)).replace('\n', ''))
    schedulerHeaders['How-Many'] = args.last

    workstationQuery = args.query
    if isinstance(workstationQuery, str):
        try:
            workstationQuery = json.loads(workstationQuery)
        except:
            workstationQuery = {}
    if not 'filters' in workstationQuery:
        workstationQuery['filters'] = {}
    if args.nodename != None:
        if not 'workstationInPlanFilter' in workstationQuery['filters']:
            workstationQuery['filters']['workstationInPlanFilter'] = {}
        if args.workstation == None:
            workstationQuery['filters']['workstationInPlanFilter']['nodeName'] = args.nodename
    if args.workstation != None:
        if not 'workstationInPlanFilter' in workstationQuery['filters']:
            workstationQuery['filters']['workstationInPlanFilter'] = {}
        workstationQuery['filters']['workstationInPlanFilter']['workstationName'] = args.workstation
        if 'nodeName' in workstationQuery['filters']['workstationInPlanFilter']:
            del workstationQuery['filters']['workstationInPlanFilter']['nodeName']

    logging.debug('Workstation filter: {0}'.format(workstationQuery))
    WorkstationList = getWorkstationList(schedulerEndpoint, schedulerHeaders, workstationQuery)
    logging.debug('Job list: {0}'.format(WorkstationList))
    if WorkstationList == None or len(WorkstationList) == 0:
        print('UNKNOWN: No Workstation found with the following request: {0}'.format(workstationQuery))
        sys.exit(CENTREON_EXIT_UNKNOWN)

    workstationRunning = []
    workstationNotRunning = []
    for workstation in WorkstationList:
        if workstation['ssmRunning']:
            workstationRunning.append(workstation['workstationInPlanKey']['name'])
        else:
            workstationNotRunning.append(workstation['workstationInPlanKey']['name'])

    if len(workstationNotRunning) == 0 and len(workstationRunning) == 1:
        print('OK: The workstation is running (iws agent): {0} '.format(', '.join(workstationRunning)))
        sys.exit(CENTREON_EXIT_OK)

    if len(workstationNotRunning) == 0 and len(workstationRunning) > 1:
        print('OK: All workstations are running (iws agent): {0}'.format(', '.join(workstationRunning)))
        sys.exit(CENTREON_EXIT_OK)

    if len(workstationNotRunning) == 1 and len(workstationRunning) == 0:
        print('CRITICAL: The workstation is not running (iws agent): {0}'.format(', '.join(workstationNotRunning)))
        sys.exit(CENTREON_EXIT_CRITICAL)

    if len(workstationNotRunning) > 1 and len(workstationRunning) == 0:
        print('CRITICAL: All workstations are not running (iws agent): {0}'.format(', '.join(workstationNotRunning)))
        sys.exit(CENTREON_EXIT_CRITICAL)

    if len(workstationNotRunning) > 0:
        print('CRITICAL: The following workstation is not running : [{0}] but some other workstation is running (details above).'.format(', '.join(workstationNotRunning)))
        for workstation in workstationNotRunning:
            print('KO: {0} is not running'.format(workstation))
        for workstation in workstationRunning:
            print('OK: {0} is running'.format(workstation))
        sys.exit(CENTREON_EXIT_CRITICAL)

    sys.exit(CENTREON_EXIT_UNKNOWN)
