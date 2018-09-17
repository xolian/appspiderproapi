#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Brandon Spruth (brandon@spruth.co)"
__copyright__ = "(C) 2018 Spruth, Co."
__contributors__ = ["Brandon Spruth"]
__status__ = "Beta"
__license__ = "MIT"

import urllib3
import json
import requests
import requests.auth
import requests.exceptions
import requests.packages.urllib3
from . import __version__ as version


class AppSpiderProApi(object):
    def __init__(self, host, username=None, password=None, token=None, verify_ssl=True, timeout=60, user_agent=None,
                 client_version='0.0.1b'):


        self.host = host
        self.username = username
        self.password = password
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.client_version = client_version

        if not user_agent:
            self.user_agent = 'appspiderpro_api/' + version
        else:
            self.user_agent = user_agent

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Set auth_type based on what's been provided
        if username is not None:
            self.auth_type = 'basic'
        elif token is not None:
            self.auth_type = 'token'
        else:
            self.auth_type = 'unauthenticated'

    def create_scan(self):
        """
        :param: TBD
        :return: Launches a scan with AppSpider Pro scanner.
        """
        pass

    def download_scan(self):
        """
        :param: TBD
        :return: Download a scan file from AppSpider Pro scanner..
        """
        pass

    def list_scans(self):
        """
        :param: TBD
        :return: List scan status from AppSpider Pro scanner..
        """
        pass

    def stop_scan(self):
        """
        :param: TBD
        :return: Stop running scan from AppSpider Pro scanner.
        """
        pass

    def delete_scan(self):
        """
        :param TBD:
        :return: Delete scan from AppSpider Pro scanner
        """

    def _request(self, method, url, params=None, files=None, data=None, headers=None):
        """Common handler for all HTTP requests."""
        if not params:
            params = {}

        if not headers:
            headers = {
                'Accept': 'application/json'
            }
            if method == 'GET' or method == 'POST':
                headers.update({'Content-Type': 'application/json'})
        headers.update({'User-Agent': self.user_agent})

        try:

            if self.auth_type == 'basic':
                response = requests.request(method=method, url=self.host + url, params=params, files=files,
                                            headers=headers, data=data,
                                            verify=self.verify_ssl,
                                            timeout=self.timeout,
                                            auth=(self.username, self.password))
            elif self.auth_type == 'certificate':
                response = requests.request(method=method, url=self.host + url, params=params, files=files,
                                            headers=headers, data=data,
                                            verify=self.verify_ssl,
                                            timeout=self.timeout,
                                            cert=self.cert)
            else:
                response = requests.request(method=method, url=self.host + url, params=params, files=files,
                                            headers=headers, data=data,
                                            timeout=self.timeout,
                                            verify=self.verify_ssl)

            try:
                response.raise_for_status()

                # Two response codes if successful, GETs return 200, PUTs return 204 with empty response text
                response_code = response.status_code
                success = True if response_code // 100 == 2 else False
                if response.text:
                    try:
                        data = response.json()
                    except ValueError:  # Sometimes the returned data isn't JSON (e.g. GetScanFormat) so return raw
                        data = response.content
                else:
                    data = ''

                return AppSpiderProResponse(success=success, response_code=response_code, data=data)
            except ValueError as e:
                return AppSpiderProResponse(success=False, message="JSON response could not be decoded {}.".format(e))
            except requests.exceptions.HTTPError as e:
                if response.status_code == 401:
                    return AppSpiderProResponse(success=False, response_code=401, message=e)
                else:
                    return AppSpiderProResponse(
                        message='There was an error while handling the request. {}'.format(response.content),
                        success=False)
        except requests.exceptions.SSLError:
            return AppSpiderProResponse(message='An SSL error occurred.', success=False)
        except requests.exceptions.ConnectionError:
            return AppSpiderProResponse(message='A connection error occurred.', success=False)
        except requests.exceptions.Timeout:
            return AppSpiderProResponse(message='The request timed out after ', success=False)
        except requests.exceptions.RequestException:
            return AppSpiderProResponse(
                message='There was an error while handling the request. {}'.format(response.content), success=False)


class AppSpiderProResponse(object):
    """Object for all AppSpiderPro API responses and errors."""

    def __init__(self, success, message='OK', response_code=-1, data=None):
        self.message = message
        self.success = success
        self.response_code = response_code
        self.data = data

    def __str__(self):
        if self.data:
            return str(self.data)
        else:
            return self.message

    def data_json(self, pretty=False):
        """Returns the data as a valid JSON string."""
        if pretty:
            return json.dumps(self.data, sort_keys=True, indent=4, separators=(',', ': '))
        else:
            return json.dumps(self.data)