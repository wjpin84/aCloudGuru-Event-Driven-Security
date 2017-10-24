"""File for managing and updating VPC Flow Log events."""

import boto3
import logging
import json
import gzip
import base64
from StringIO import StringIO


class VpcEvent:

    """Domain object for VpcEvent."""

    def __init__(self, record):
        """Set constructor, takes a record parses and gets information."""
        self.__instanceId = None
        self.__interfaceId = record['interface_id']
        self.__src = {addr: record['srcaddr'], port: record['srcport']}
        self.__dst = {addr: record['dstaddr'], port: = record['dstport']}

    def setInstanceId(self, instanceId):
        """Sets the instance id for the vpc event."""
        self.__instanceId

    def getInstanceId(self):
        """Return the instance id of a vpc event."""
        return self.__instanceId

    def getInterfaceId(self):
        """Return the interfade id of a vpc event."""
        return self.__interfaceId

    def isUnknown(self):
        """Return boolean if instance id is unkown."""
        return self.__instanceId is None

    def getSource(self):
        """Return the source ip address and port of the event."""
        return self.__src

    def getDestination(self):
        """Return the destination ip address and port of the event."""
        return self.__dst

    def toString(self):
        """Return string representation of object."""
        return "Instance:{}\t Interface:{}\t SrcAddr:{}\t SrcPort:{}\t" +
        "DstAddr:{}\t DstPort:{}\t".format(
                self.__instanceId,
                self.__interfaceId,
                self.__src['addr'],
                self.__src['port'],
                self.__dst['addr'],
                self.__dst['port']
            )


class VpcEventUtility:

    logger = logging.getLogger(__name__)

    """Utility class for VpcEvent"""

    __snsArn = "arn:aws:sns:us-east-1:012345678901:instanceKiller"

    def parseEvent(cloudwatchEvent):
        """Return parsed events from cloudwatch."""
        # get CloudWatch logs
        data = str(event['awslogs']['data'])
        # decode and uncompress CloudWatch logs
        logs = gzip.GzipFile(fileobj=StringIO(
                data.decode('base64', 'strict'))).read()
        # convert the log data from JSON into a dictionary
        return json.loads(logs)

    def killInstance(vpcEvent):
        """Kill the instance in the event."""
        instance = __getInstanceById(self.__instanceId)
        __stopInstance(instance)
        snapshotId = __snapshotInstance(instance)
        try:
            response = instance.terminate(DryRun=dryrun)
        except(ex):
            raise Exception("Unable to terminate instance to kill. {}"
                            .format(instanceId))

        sendNotification(instanceId, snapshotId)

    def getInstanceIdByInterfaceId(eniId):
        """Return the ec2 instances given the interface id.

        Return the ec2 instance given the interfaceß id, if instance id does
        not exist, then return false for unknown interface.
        """
        ec2 = boto3.resource('ec2')
        instanceId = None
        try:
            network_interface = ec2.NetworkInterface(eniId)
            instanceId = network_interface.attachment['InstanceId']
        except(ex):
            logger.info("Interface: {} is unknown".format(eniId))
        return instanceId

    def __sendNotification(instanceId, snapshotId):
        """Send a notification that an instance has been terminated."""
        client = boto3.client('sns')
        msg = "Instance {} has been terminated.  Snapshot {} created."
        try:
            response = client.publish(
                TopicArn=__snsArn,
                Message=msg.format(instanceId, snapshotId)
                Subject='InstanceKiller has terminated an instance'
            )
            logger.info("SNS Notification sent.")
        except(ex):
            logger.error("Unable to send SNS notification.")

    def __snapshotVolumeById(volumeId, instanceId):
        """Create a snapshot of a volume by volume id."""
        try:
            ec2 = boto3.resource('ec2')
            volume = ec2.Volume(volumeId)
        except(ex):
            Exception("Unable to find volume {} to snapshot".format(volumeId))

        desc =
        snapshot = volume.create_snapshot(
            DryRun=dryrun,
            Description=desc.format(instanceId)
        )

        return snapshot.id

    def __snapshotInstance(instance):
        """Create a snapshot of every volume inside an instance."""
        volume_iterator = instance.volumes.all()
        for volume in volume_iterator:
            try:
                snapshot = snapshotVolumeById(volume.id, instanceId)
                logger.info("Snapshot for instance {} volume {} snapshot {}"
                            .format(instanceId, volume.id, snapshot))
            except(ex):
                logger.warning(ex.msg)

    def __stopInstance(instance):
        """Stop ec2 instance given the ec2 object."""
        logger.info("Sending stop message to instance. {}".format(instanceId))
        try:
            response = instance.stop(
                DryRun=dryrun,
                Force=True
            )
        except(ex):
            raise Exception("Unable to stop instance. {}".format(instanceId))
