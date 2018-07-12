"""
(c) 2018, Archie Gunasekara <contact@achinthagunasekara.com>
Module to handle encrypting and decrypting of items with KMS
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
from os.path import basename
from ansible.errors import AnsibleFilterError

try:
    import boto3
    from aws_encryption_sdk.key_providers.kms import KMSMasterKey
    from aws_encryption_sdk import KMSMasterKeyProvider, encrypt, decrypt
    from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError
    HAS_DEPENDENCIES = True
except ImportError:
    HAS_DEPENDENCIES = False


def role_arn_to_session(**args):
    """
    Refer:
    http://boto3.readthedocs.io/en/latest/reference/services/sts.html#STS.Client.assume_role
    Usage :
        session = role_arn_to_session(
            RoleArn='arn:aws:iam::012345678901:role/example-role',
            RoleSessionName='ExampleSessionName')
        client = session.client('sqs')
    """
    client = boto3.client('sts')
    response = client.assume_role(**args)
    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])


def get_boto_session(**kwargs):
    """
    Get boto3 session object.
    """
    try:
        if 'profile_name' in kwargs:
            return boto3.session.Session(profile_name=kwargs['profile_name'])
        elif 'role_to_assume' in kwargs:
            return role_arn_to_session(
                RoleArn=kwargs['role_to_assume'],
                RoleSessionName=basename(kwargs['role_to_assume'])
            )
        elif 'aws_access_key_id' in kwargs and 'aws_secret_access_key' in kwargs:
            return boto3.Session(
                aws_access_key_id=kwargs['aws_access_key_id'],
                aws_secret_access_key=kwargs['aws_secret_access_key'],
            )
        return boto3.session.Session()
    except Exception as ex:
        raise AnsibleFilterError("Something went wrong while creating a "
                                 "boto3 session in aws_kms_plugin - {0}".format(ex))


def get_key_provider(key_arn, **kwargs):
    """
    Get KMS key provider object.
    Args:
      key_arn (str): AWS ARN to the KMS key.
    Returns:
      KMSMasterKeyProvider: KMS Master Key Provider object.
    """

    if not HAS_DEPENDENCIES:
        raise AnsibleFilterError('You need to install "boto3" and "aws_encryption_sdk"'
                                 'before using aws_kms filter')

    if 'region_name' in kwargs:
        region_name = kwargs['region']
    else:
        region_name = 'us-east-1'

    boto_session = get_boto_session(**kwargs)
    client = boto_session.client('kms', region_name=region_name)
    key_provider = KMSMasterKeyProvider()
    regional_master_key = KMSMasterKey(client=client, key_id=key_arn)
    key_provider.add_master_key_provider(regional_master_key)
    return key_provider


def aws_kms_encrypt(plaintext, key_arn, **kwargs):
    """
    Encrypt with KMS.
    Args:
        plaintext (str): Plain text item to ecrypt.
        key_arn (str): AWS ARN to the KMS key.
    Returns:
        str: Encrypted item with KMS.
    """
    try:
        ciphertext, dummy = encrypt(
            source=plaintext,
            key_provider=get_key_provider(key_arn=key_arn, **kwargs)
        )
        return base64.b64encode(ciphertext)
    except AWSEncryptionSDKClientError as kms_ex:
        raise AnsibleFilterError("Unable to encrypt vaule using KMS - {0}".format(kms_ex))


def aws_kms_decrypt(ciphertext, key_arn, **kwargs):
    """
    Decrypt with KMS.
    Args:
        ciphertext (str): Encrypted item to decrypt.
        key_arn (str): AWS ARN to the KMS key.
    Returns:
        str: Decrypted plaintext item.
    """
    try:
        cycled_plaintext, dummy = decrypt(
            source=base64.b64decode(ciphertext),
            key_provider=get_key_provider(key_arn=key_arn, **kwargs)
        )
        return cycled_plaintext.rstrip()
    except AWSEncryptionSDKClientError as kms_ex:
        raise AnsibleFilterError("Unable to encrypt vaule using KMS - {0}".format(kms_ex))


class FilterModule(object):  # pylint: disable=too-few-public-methods
    """
    Filter module to provide functions.
    """
    def filters(self):  # pylint: disable=no-self-use
        """
        Filter module to provide functions.
        """
        return {
            'aws_kms_encrypt': aws_kms_encrypt,
            'aws_kms_decrypt': aws_kms_decrypt
        }
