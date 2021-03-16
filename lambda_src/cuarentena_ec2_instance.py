# -*- coding: utf-8 -*-

import boto3
import os
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
    global_vars['tag_name']                 = "cuarentena_ec2_instancia"
    global_vars['status']                   = True
    return global_vars

def get_cuarentena_sg_id(inst_id):
    ec2_resource = boto3.resource('ec2')
    ec2_client = boto3.client('ec2')

    q_sg_name="dtt-cuarentena"

    inst_attr = ec2_client.describe_instances( InstanceIds=[inst_id] )['Reservations'][0]['Instances'][0]
    if inst_attr:
        inst_vpc_id = inst_attr.get('VpcId')

    # Check or create the cuarentena SG
    try:    
        result = ec2_client.describe_security_groups(
            Filters=[
                    {
                        'Name': 'group-name',
                        'Values': [q_sg_name]
                    },
                    {
                        'Name': 'vpc-id',
                        'Values': [inst_vpc_id]
                    }
                ]
            )
        if result['SecurityGroups']: 
            cuarentena_sg_id = result['SecurityGroups'][0]['GroupId']
            logger.info(f"Se ha encontrado una cuarentena existente sg_id: {cuarentena_sg_id}")

        else:
            result = ec2_client.create_security_group(
                    Description='Grupo de seguridad de cuarentena. No se deben adjuntar reglas de entrada o salida.',
                    GroupName=q_sg_name,
                    VpcId=inst_vpc_id 
                    )

            # When a SG is created, AWS automatically adds in an outbound rule we need to delete
            security_group = ec2_resource.SecurityGroup(result['GroupId'])
            delete_outbound_result = security_group.revoke_egress(
                GroupId=result['GroupId'],
                IpPermissions=[{'IpProtocol':'-1','IpRanges': [{'CidrIp':'0.0.0.0/0'}]}]
                )
            tag = security_group.create_tags(Tags=[
                {'Key': 'Name','Value': "cuarentena-SG"}
                ]
            )
            logger.info(f"Nuevo grupo de seguridad de cuarentena creado. sg_id: {result['GroupId']}")
            cuarentena_sg_id = result['GroupId']
        
    except ClientError as e:
        logger.info(f"No se puede encontrar o crear un grupo de seguridad de cuarentena")
        logger.info(f"ERROR: {str(e)}")
        exit

    return cuarentena_sg_id

def cuarentena_ec2_instance(inst_id, cuarentena_sg_id):

    resp = {'status': False, 'cuarentena_sg_status': [] }

    ec2_resource = boto3.resource('ec2')

    # Attach the instance to only the cuarentena SG
    try:
        result = ec2_resource.Instance(inst_id).modify_attribute(Groups=[cuarentena_sg_id])  
        responseCode = result['ResponseMetadata']['HTTPStatusCode']
        if responseCode >= 400:
            logger.info(f"No se puede modificar el grupo de seguridad de la instancia")
            logger.info(f"ERROR:{str(result)}")
            resp['error_message'] = str(result)
        else:
            logger.info(f"Instance:{inst_id} en cuarentena con el SecurityGroup:{cuarentena_sg_id}")
            resp['status'] = True
            resp['cuarentena_sg_status'].append( {'instance_id':inst_id, 'cuarentena_sg_added':True, 'cuarentena_sg_id': cuarentena_sg_id} )
    except ClientError as e:
        logger.info(f"No se puede modificar el grupo de seguridad de la instancia")
        logger.info(f"ERROR: {str(e)}")
        resp['cuarentena_sg_status'].append( {'instance_id':inst_id, 'cuarentena_sg_added':False, 'error_message':str(e)} )
    return resp

def lambda_handler(event, context):
    logger.info(f"Event:{event}")
    resp = {'status':False}
    GUARDDUTY_FINDING_TYPE="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"
    if 'detail' in event:
        if event.get('detail').get('type') == GUARDDUTY_FINDING_TYPE:
            principal_id = event.get('detail').get('resource').get('accessKeyDetails').get('principalId')
            role_name = event.get('detail').get('resource').get('accessKeyDetails').get('userName')
            if principal_id:
                inst_id = principal_id.split(":")[1]
                if inst_id:
                    logger.info(f"Ir a la instancia en cuarentena :{inst_id}")
                    cuarentena_sg_id = get_cuarentena_sg_id(inst_id)
                    resp = cuarentena_ec2_instance(inst_id, cuarentena_sg_id)
    return resp

if __name__ == '__main__':
    lambda_handler(None, None)
