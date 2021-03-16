# -*- coding: utf-8 -*-

import boto3
import os
import json
from botocore.exceptions import ClientError
import logging


# Initialize Logger
logger = logging.getLogger()
logging.basicConfig(
    format="[%(asctime)s] %(levelname)s [%(module)s.%(funcName)s:%(lineno)d] %(message)s", datefmt="%H:%M:%S"
)
logger.setLevel(os.getenv('log_level', logging.INFO))


def set_global_vars():
    global_vars = {'status': False}
    global_vars['Owner']                    = "DTT"
    global_vars['Environment']              = "Prod"
    global_vars['region_name']              = "us-east-1"
    global_vars['cuarentena_policy_name']    = f"cuarentena_policy_{global_vars['Owner']}"
    global_vars['tag_name']                 = "cuarentena_iam_role"
    global_vars['status']                   = True
    return global_vars


def create_deny_all_policy(cuarentena_policy_name):
    """
    Create the cuarentena IAM policy that'll be applied to the users or roles that need to be locked down.
    """
    # Create IAM client
    iam_client = boto3.client('iam')

    policy_created = False
    
    # Create a policy
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {   
                "Sid": "DenyALLPermissions",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    try:
        resp = iam_client.create_policy(
            PolicyName=cuarentena_policy_name,
            PolicyDocument=json.dumps(deny_policy)
        )
        responseCode = resp['ResponseMetadata']['HTTPStatusCode']
        if responseCode >= 400:
            logger.info(f"ERROR: {str(resp)}")
        else:
            logger.info(f"IAM deny-all policy creada correctamente.")
            policy_created = True
    except ClientError as e:
        logger.info(f"No se puede crear el grupo de políticas DENY ALL")
        logger.info(f"ERROR: {str(e)}")
    return policy_created


def check_deny_policy_exists(cuarentena_policy_arn):
    """
    Poll the account and check if the cuarentena_deny_all policy exists. If not - make it
    """
    # Create IAM client
    iam_client = boto3.client('iam')
    policy_exists = False
    try:
        #Check to see if the deny policy exists in the account currently
        get_policy_response = iam_client.get_policy(PolicyArn=cuarentena_policy_arn)
        
        if get_policy_response['ResponseMetadata']['HTTPStatusCode'] < 400:
            logger.info(f"IAM DENY ALL policy:'{cuarentena_policy_arn} existe")
            policy_exists = True
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            logger.info(f"IAM DENY ALL policy:'{cuarentena_policy_arn} no se encuentra")
        else:
            logger.info(f"ERROR:{str(e)}")
    return policy_exists


def add_cuarentena_policy_to_role(role,policy_arn):
    """
    Attach cuarentena policy to role
    """
    resp = {'status': False, 'is_cuarentenad':False}
    # Create IAM client
    iam_client = boto3.client('iam')
    
    try:
        attach_policy_response = iam_client.attach_role_policy(
            RoleName=role,
            PolicyArn=policy_arn
        )
        logger.info(f"Deny policy adjunta al role:'{role}'")
        resp['status'] = True
        resp['cuarentena_role_status'] = {
            'role_name':role,
            'is_cuarentenad':True,
            'cuarentena_policy':policy_arn
        }
    except ClientError as e:
        logger.info("No es posible adjuntar la policy al role:'{role}'")
        logger.info(f"ERROR:{str(e)}")
        resp['error_message'] = str(e)
    return resp


def lambda_handler(event, context):

    global_vars = set_global_vars()

    logger.info(f"Event:{event}")
    resp = {'status':False}

    account_id = boto3.client('sts').get_caller_identity()['Account']
    cuarentena_policy_arn = f"arn:aws:iam::{account_id}:policy/{global_vars.get('cuarentena_policy_name')}"

    GUARDDUTY_FINDING_TYPE="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"
    if 'detail' in event:
        if event.get('detail').get('type') == GUARDDUTY_FINDING_TYPE:
            cuarentena_role = event.get('detail').get('resource').get('accessKeyDetails').get('userName')

    try:
        policy_exists = check_deny_policy_exists(cuarentena_policy_arn)
        if not policy_exists:
            logger.info(f"Creando IAM DENY ALL policy")
            policy_created = create_deny_all_policy(global_vars.get('cuarentena_policy_name'))
            if not policy_created:
                resp['error_message'] ="No se encuentra la policy y no es posible crearla"
                return resp
        resp = add_cuarentena_policy_to_role(cuarentena_role,cuarentena_policy_arn)
    except ClientError as e:
        logger.info(f"El role de cuarentena no esta disponible")
        logger.info(f"ERROR:{str(e)}")
    return resp


if __name__ == '__main__':
    lambda_handler(None, None)