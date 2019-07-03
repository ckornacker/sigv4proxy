# -*- coding: utf-8 -*-
"""AWS SigV4 encapsulation for mitmproxy.

This addon transparently signs AWS REST request with SigV4
"""

import os
import re
from urllib.parse import parse_qs, urlencode, urlparse

import boto3
from botocore.auth import S3SigV4Auth, SigV4Auth
from botocore.awsrequest import AWSRequest
from mitmproxy import ctx


class SigV4:
    def __init__(self):
        self.awsre = re.compile(
            r'[a-z0-9\-]+\.(?P<service>[a-z0-9\-]+).?(?P<region>[a-z0-9\-]+)?\.amazonaws.com'
        )

        self.profile = os.getenv('AWS_PROFILE', 'default')
        self.region = os.getenv('AWS_REGION', 'ap-southeast-2')

        ctx.log.info(
            'Loading AWS SigV4 for profile "%s" and default region "%s"' %
            (self.profile, self.region))

    def request(self, flow):
        awsm = self.awsre.match(flow.request.host)

        if awsm.group() is None:
            # This is not an amazonaws request

            return

        region_name = awsm.group('region') or self.region
        service_name = awsm.group('service')

        session = boto3.Session(region_name=region_name)
        credentials = session.get_credentials()

        url = urlparse("{0}://{1}{2}".format(flow.request.scheme,
                                             flow.request.host,
                                             flow.request.path))
        path = url.path or '/'
        querystring = ''

        if url.query:
            querystring = '?' + \
                urlencode(
                    parse_qs(url.query, keep_blank_values=True), doseq=True)

        headers = {k.lower(): v for k, v in flow.request.headers.items()}
        location = headers.get('host') or url.netloc
        safe_url = url.scheme + '://' + \
            location.split(':')[0] + path + querystring
        awsrequest = AWSRequest(method=flow.request.method.upper(),
                                url=safe_url,
                                data=flow.request.content)

        SigV4Alg = SigV4Auth

        if service_name == 's3':
            SigV4Alg = S3SigV4Auth

        SigV4Alg(credentials, service_name, region_name).add_auth(awsrequest)
        ctx.log.info('signing "%s" request with key "%s"' %
                     (service_name, credentials.access_key))

        flow.request.headers.update(dict(awsrequest.headers.items()))


addons = [SigV4()]
