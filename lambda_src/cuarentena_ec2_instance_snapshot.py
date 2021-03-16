# -*- coding: utf-8 -*-

import boto3
import os
import logging

# Initialize Logger
logger = logging.getLogger()
logging.basicConfig(
    format="[%(asctime)s] %(levelname)s [%(module)s.%(funcName)s:%(lineno)d] %(message)s", datefmt="%H:%M:%S"
)
logger.setLevel(os.getenv('log_level', logging.INFO))

def create_instance_snapshot( inst_id ):
    resp = {'status': False, 'cuarentena_snapshot_status': [] }
    client = boto3.client('ec2')
    response = client.describe_instances(
        InstanceIds=[
            inst_id
        ]
    )
    volumeID = response['Reservations'][0]['Instances'][0]['BlockDeviceMappings'][0]['Ebs']['VolumeId']
    logger.info(f"volumeID: {volumeID}")
    SnapShotDetails = client.create_snapshot(
        Description='Instancia Aislada',
        VolumeId=volumeID
    )
    # TODO Dump Response into S3 - response
    # TODO Dump Response details into Snapshot - SnapShotDetails['SnapshotId']

    logger.info(f"SnapShotDetails: {SnapShotDetails['SnapshotId']}")

    tagresponse = client.create_tags(
        Resources=[
            SnapShotDetails['SnapshotId'],
        ],
        Tags=[
            {
                'Key': 'Name',
                'Value': 'CUARENTENA-INSTANCIA-SNAPSHOT'
            },
            {
                'Key': 'InstanceId',
                'Value': f"{inst_id}"
            },
        ]
    )

    waiter = client.get_waiter('snapshot_completed')
    waiter.wait(
        SnapshotIds=[
            SnapShotDetails['SnapshotId'],
        ]
    )
    resp['status'] = True
    resp['cuarentena_snapshot_status'].append( {'instance_id':inst_id, 
                                'snapshot_successful':True, 
                                'snapshot_id':SnapShotDetails['SnapshotId']
                                }
                        )
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
                logger.info(f"Ve al snapshot de cuarentena creado de la instancia :{inst_id}")
                resp = create_instance_snapshot(inst_id)
    return resp

if __name__ == '__main__':
    lambda_handler({}, {})