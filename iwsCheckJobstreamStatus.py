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
DEFAULT_QUERY            = {"filters": {}}
DEFAULT_JOBSTREAM_FAILED_COMMON_STATUS   = ['ERROR', 'BLOCKED', 'UNDEFIDED']
DEFAULT_JOBSTREAM_FAILED_INTERNAL_STATUS = ['ABEND', 'STUCK']

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
        Loads the values from the .env file located next to the script.
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

def getJobstreamList(schedulerEndpoint, schedulerHeader, jobstreamQuery):
    """
        Function querying IWS to retrieve the jobstream list based on a query.
    """
    jobstreamList = postRequest('{0}/jobstream/query'.format(schedulerEndpoint), schedulerHeader, jobstreamQuery)
    if jobstreamList == None:
        logging.error('Jobstream list get request failed : {0}'.format(jobstreamList))
        return None
    return jobstreamList
		
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
    parser.add_argument('-j', '--jobstream', type=str,
                        help='Overload the name of the jobstream (regex is allowed, ex: "*" or "VAD*"). By default, the search is done on all jobstreams.')
    parser.add_argument('-w', '--workstation', type=str,
                        help='Overload the name of the workstation where to look for the jobstream (regex is allowed, ex: "*" or "VAD*"). By default, the search is done on all the workstations.')
    parser.add_argument('-n', '--nodename', type=str,
                        help="Alternatively to the workstation name, search according to the node name (i.e. the host name). This option is not set if --workstation is used")

    parser.add_argument('-q', '--query', type=str, default=DEFAULT_QUERY,
                        help='Advanced option to query the IWS API directly. See: https://start.wa.ibmserviceengage.com/twsd/#/%5BPlan%5D%20Job/queryJobInPlan to know the various options of query. The other selection options of the query always override this option.')
    parser.add_argument('--last', type=int, default=DEFAULT_ARG_LAST,
                        help='Allows you to specify the maximum number of entity returned by the filter. By default, only one value is returned.')

    parser.add_argument('-f', '--filter-jobstream', type=str, default=None,
                        help='Additinnal filter to apply on jobstream name after requested data. Usefull when we want to use more complex logic to select jobstream name (regex allowed, see https://regex101.com).')

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

    if args.jobstream == None or args.jobstream == '':
        print("UNKNOWN: Missing jobstream parameter. Please provide --jobstream parameter.")
        sys.exit(CENTREON_EXIT_UNKNOWN)

    schedulerEndpoint = '{0}/twsd/plan/{1}'.format(args.server, args.plan)
    schedulerHeaders = DEFAULT_HEADERS
    schedulerHeaders['Authorization'] = 'Basic {0}'.format(base64.encodestring('{0}:{1}'.format(args.login, args.password)).replace('\n', ''))
    schedulerHeaders['How-Many'] = args.last
    logging.debug('Headers request: {0}'.format(schedulerHeaders))

    jobstreamQuery = args.query
    if isinstance(jobstreamQuery, str):
        try:
            jobstreamQuery = json.loads(jobstreamQuery)
        except:
            jobstreamQuery = {}
    if not 'filters' in jobstreamQuery:
        jobstreamQuery['filters'] = {}
    if args.workstation != None:
        if not 'jobStreamInPlanFilter' in jobstreamQuery['filters']:
            jobstreamQuery['filters']['jobStreamInPlanFilter'] = {}
        jobstreamQuery['filters']['jobStreamInPlanFilter']['workstationName'] = args.workstation
    if args.jobstream != None:
        if not 'jobStreamInPlanFilter' in jobstreamQuery['filters']:
            jobstreamQuery['filters']['jobStreamInPlanFilter'] = {}
        jobstreamQuery['filters']['jobStreamInPlanFilter']['jobStreamName'] = args.jobstream

    logging.debug('Jobstream filter: {0}'.format(jobstreamQuery))
    jobstreamList = getJobstreamList(schedulerEndpoint, schedulerHeaders, jobstreamQuery)
    logging.debug('Jobstream list: {0}'.format(jobstreamList))
    if jobstreamList == None:
        print('UNKNOWN: No Jobstream found with the following request: {0}'.format(jobstreamQuery))
        sys.exit(CENTREON_EXIT_UNKNOWN)
    if len(jobstreamList) == 0:
        print('UNKNOWN: No Jobstream found with the following request: {0}'.format(jobstreamQuery))
        sys.exit(CENTREON_EXIT_UNKNOWN)

    jobstreamSuccess = []
    jobstreamFailed = []
    for jobstream in jobstreamList:
        if args.filter_jobstream is not None:
            if re.search(args.filter_jobstream, jobstream['key']['name']) is None:
                logging.debug('Bypass {0}#{1}({2})'.format(jobstream['key']['workstationKey']['originalName'], jobstream['key']['name'], jobstream['status']['commonStatus']))
                continue
        if jobstream['status']['commonStatus'] not in DEFAULT_JOBSTREAM_FAILED_COMMON_STATUS and jobstream['status']['internalStatus'] not in DEFAULT_JOBSTREAM_FAILED_INTERNAL_STATUS:
            jobstreamSuccess.append('{0}#{1}({2})'.format(jobstream['key']['workstationKey']['originalName'], jobstream['key']['name'], jobstream['status']['commonStatus']))
        else:
            jobstreamFailed.append('{0}#{1}({2})'.format(jobstream['key']['workstationKey']['originalName'], jobstream['key']['name'], jobstream['status']['commonStatus']))

    if len(jobstreamFailed) == 0 and len(jobstreamSuccess) == 1:
        print('OK: The jobstream is not in a failed state: {0} '.format(', '.join(jobstreamSuccess)))
        sys.exit(CENTREON_EXIT_OK)

    if len(jobstreamFailed) == 0 and len(jobstreamSuccess) > 1:
        print('OK: No jobstream in a failed state.')
        sys.exit(CENTREON_EXIT_OK)

    if len(jobstreamFailed) == 1 and len(jobstreamSuccess) == 0:
        print('CRITICAL: The jobstream is in a failed state: {0}'.format(', '.join(jobstreamFailed)))
        sys.exit(CENTREON_EXIT_CRITICAL)

    if len(jobstreamFailed) > 0:
        print('CRITICAL: {0} jobstream in a failed state : {1}'.format(len(jobstreamFailed), ', '.join(jobstreamFailed)))
        sys.exit(CENTREON_EXIT_CRITICAL)

    print('UNKNOWN: No Jobstream found. Please execute command with debug option.')
    sys.exit(CENTREON_EXIT_UNKNOWN)
