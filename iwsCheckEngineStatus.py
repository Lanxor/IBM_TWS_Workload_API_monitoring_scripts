#! /usr/bin/env python
# -*- coding: utf-8

import os
import sys
import base64
import urllib3
import argparse
import logging
import json
import time

DEFAULT_ARG_DEBUG = False

DEFAULT_SERVER           = ''
DEFAULT_LOGIN            = ''
DEFAULT_PASSWORD         = ''
DEFAULT_HEADERS          = {"Content-Type":"application/json", "Accept":"application/json", "User-Agent": "Python script", "How-Many": 100}

CENTREON_EXIT_CRITICAL = 2
CENTREON_EXIT_WARNING  = 1
CENTREON_EXIT_OK       = 0
CENTREON_EXIT_UNKNOWN  = 3

# To disable certificate verification, value is CERT_NONE
# You can use --insecure option to set to CERT_NONE
URLLIB_OPTION_CERT_REQ = "CERT_REQUIRED"

urllib3.disable_warnings()
logging.basicConfig(level=logging.WARNING, format='%(asctime)s [%(levelname)s]: %(message)s')

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


def getEngineInfos(schedulerEndpoint, schedulerHeader):
    """
        Function querying IWS to retrieve the engine infos.
    """
    engineInfo = getRequest('{0}/engine/info'.format(schedulerEndpoint), schedulerHeader)
    if engineInfo == None:
        logging.error('Engine info get request failed : {0}'.format(engineInfo))
        return None
    return engineInfo


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Script to interact with the IWS scheduler API to retrieve engine status and check if its ok.')

    parser.add_argument('--server', type=str, default=DEFAULT_SERVER,
                        help='The address of the IWS scheduler server to query.')
    parser.add_argument('--login', type=str, default=DEFAULT_LOGIN,
                        help='The login username.')
    parser.add_argument('--password', type=str, default=DEFAULT_PASSWORD,
                        help='The user\'s password.')

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
        print("UNKNOWN: Missing scheduler server. Please provide --server with non empty value.")
        sys.exit(CENTREON_EXIT_UNKNOWN)

    if args.login == '':
        print("UNKNOWN: Missing scheduler login. Please provide --login with non empty value.")
        sys.exit(CENTREON_EXIT_UNKNOWN)

    if args.password == '':
        print("UNKNOWN: Missing scheduler password. Please provide --password with non empty value.")
        sys.exit(CENTREON_EXIT_UNKNOWN)

    schedulerEndpoint = '{0}/twsd'.format(args.server)
    schedulerHeaders = DEFAULT_HEADERS
    schedulerHeaders['Authorization'] = 'Basic {0}'.format(base64.encodestring('{0}:{1}'.format(args.login, args.password)).replace('\n', ''))

    engineInfos = getEngineInfos(schedulerEndpoint, schedulerHeaders)
    infos = {
        'server' : args.server,
        'status' : engineInfos['synphonyBatchManStatus'],
        'version' : engineInfos['version'],
        'role' : engineInfos['engineType'],
        'startPlan' : engineInfos['synphonyPlanStart'].split('T')[0],
        'endPlan' : engineInfos['synphonyPlanEnd'].split('T')[0],
        'datePlan' : engineInfos['synphonyPlanStart'].split('T')[0] + "/" + engineInfos['synphonyPlanEnd'].split('T')[0]
    }

    logging.debug(infos)

    if infos['status'] != 'ENGINE_STATUS_LIVES':
        print('CRITICAL: IWS Engine is not ENGINE_STATUS_LIVES! ({1}/{2}/{3}/{4})'.format(infos['status'], infos['version'], infos['role'], infos['datePlan']))
        print(infos)
        sys.exit(CENTREON_EXIT_CRITICAL)

    if infos['endPlan'] < time.strftime("%Y-%m-%d"):
        print('CRITICAL: Error during Plan creation, the date of the plan is in the past! ({1}/{2}/{3}/{4})'.format(infos['status'], infos['version'], infos['role'], infos['datePlan']))
        print(infos)
        sys.exit(CENTREON_EXIT_CRITICAL)

    print('OK: Status of {0} engine is good ({1}/{2}/{3}/{4}).'.format(infos['server'], infos['status'], infos['version'], infos['role'], infos['datePlan']))
    print(infos)
    sys.exit(CENTREON_EXIT_OK)
    