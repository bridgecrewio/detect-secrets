import hashlib
import hmac
from datetime import datetime
from datetime import timezone
from typing import List

import requests

from ..constants import VerifiedResult
from ..util.code_snippet import CodeSnippet
from .base import RegexBasedDetector


class IbmCosHmacDetector(RegexBasedDetector):
    """Scans for IBM Cloud Object Storage HMAC credentials."""
    # requires 3 factors
    #
    #   access_key: access_key_id
    #   secret_key: secret_access_key
    #   host, defaults to 's3.us.cloud-object-storage.appdomain.cloud'

    secret_type = 'IBM COS HMAC Credentials'

    token_prefix = r'(?:(?:ibm)?[-_]?cos[-_]?(?:hmac)?|)'
    password_keyword = r'(?:secret[-_]?(?:access)?[-_]?key)'
    password = r'([a-f0-9]{48}(?![a-f0-9]))'
    denylist = (
        RegexBasedDetector.build_assignment_regex(
            prefix_regex=token_prefix,
            secret_keyword_regex=password_keyword,
            secret_regex=password,
        ),
    )

    def verify(  # type: ignore[override]
        self,
        secret: str,
        context: CodeSnippet,
    ) -> VerifiedResult:
        key_id_matches = find_access_key_id(context)

        if not key_id_matches:
            return VerifiedResult.UNVERIFIED

        try:
            for key_id in key_id_matches:
                verify_result = verify_ibm_cos_hmac_credentials(key_id, secret)
                if verify_result:
                    return VerifiedResult.VERIFIED_TRUE
        except requests.exceptions.RequestException:
            return VerifiedResult.UNVERIFIED

        return VerifiedResult.VERIFIED_FALSE


def find_access_key_id(context: CodeSnippet) -> List[str]:
    key_id_keyword_regex = r'(?:access[-_]?(?:key)?[-_]?(?:id)?|key[-_]?id)'
    key_id_regex = r'([a-f0-9]{32})'

    regex = RegexBasedDetector.build_assignment_regex(
        prefix_regex=IbmCosHmacDetector.token_prefix,
        secret_keyword_regex=key_id_keyword_regex,
        secret_regex=key_id_regex,
    )

    return [
        match
        for line in context
        for match in regex.findall(line)
    ]


def hash(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def createSignatureKey(key: str, datestamp: str, region: str, service: str) -> bytes:  # noqa: N802
    key_date = hash(('AWS4' + key).encode('utf-8'), datestamp)
    key_string = hash(key_date, region)
    key_service = hash(key_string, service)
    key_signing = hash(key_service, 'aws4_request')
    return key_signing


def verify_ibm_cos_hmac_credentials(
    access_key: str,
    secret_key: str,
    host: str = 's3.us.cloud-object-storage.appdomain.cloud',
) -> bool:
    response = query_ibm_cos_hmac(access_key, secret_key, host)
    return response.status_code == 200


def query_ibm_cos_hmac(
    access_key: str,
    secret_key: str,
    host: str = 's3.us.cloud-object-storage.appdomain.cloud',
) -> requests.Response:
    # Sample code referenced from link below
    # https://cloud.ibm.com/docs/services/cloud-object-storage/api-reference?topic=cloud-object-storage-hmac-signature  # noqa: E501

    # request elements
    http_method = 'GET'
    # region is a wildcard value that takes the place of the AWS region value
    # as COS doesn't use the same conventions for regions, this parameter can accept any string
    region = 'us-standard'
    endpoint = 'https://{}'.format(host)
    bucket = ''  # add a '/' before the bucket name to list buckets
    object_key = ''
    request_parameters = ''

    # assemble the standardized request
    time = datetime.now(timezone.utc)
    timestamp = time.strftime('%Y%m%dT%H%M%SZ')
    datestamp = time.strftime('%Y%m%d')

    standardized_resource = '/' + bucket + '/' + object_key
    standardized_querystring = request_parameters
    standardized_headers = 'host:' + host + '\n' + 'x-amz-date:' + timestamp + '\n'
    signed_headers = 'host;x-amz-date'
    payload_hash = hashlib.sha256(b'').hexdigest()

    standardized_request = (
        http_method + '\n'
        + standardized_resource + '\n'
        + standardized_querystring + '\n'
        + standardized_headers + '\n'
        + signed_headers + '\n'
        + payload_hash
    ).encode('utf-8')

    # assemble string-to-sign
    hashing_algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = datestamp + '/' + region + '/' + 's3' + '/' + 'aws4_request'
    sts = (
        hashing_algorithm + '\n'
        + timestamp + '\n'
        + credential_scope + '\n'
        + hashlib.sha256(standardized_request).hexdigest()
    )

    # generate the signature
    signature_key = createSignatureKey(secret_key, datestamp, region, 's3')
    signature = hmac.new(
        signature_key,
        (sts).encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()

    # assemble all elements into the 'authorization' header
    v4auth_header = (
        hashing_algorithm + ' '
        + 'Credential=' + access_key + '/' + credential_scope + ', '
        + 'SignedHeaders=' + signed_headers + ', '
        + 'Signature=' + signature
    )

    # create and send the request
    headers = {'x-amz-date': timestamp, 'Authorization': v4auth_header}
    # the 'requests' package automatically adds the required 'host' header
    request_url = endpoint + standardized_resource + standardized_querystring

    request = requests.get(request_url, headers=headers)

    return request
