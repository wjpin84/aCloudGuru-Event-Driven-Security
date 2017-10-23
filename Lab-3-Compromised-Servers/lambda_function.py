#! /usr/bin/python
"""Lambda for Shutting down compromised servers.

AWS Lambda function is to support event-driven security based on evaluating.
the VPC Flow Logs to see if any EC2 instances have been compromised.  In the
event of a compromise will send a SNS notification to shutdown the EC2 instance
that will be set to start a fresh instance.

"""

import json
import gzip
import base64
from StringIO import StringIO
import sets
import urllib2
import boto3
import logging
from netaddr import IPNetwork, IPAddress

# User variables
dryrun = False
allowAWS = True
exceptions = [
    {"cidr": "0.0.0.0/0", "port": "123"}
]
snsArn = "arn:aws:sns:us-east-1:012345678901:instanceKiller"

# Built in variables
aws_data_source_url = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
aws_service = "AMAZON"
aws_ports = ["80", "443"]

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def getInstanceIdByInterfaceId(eniId):
    """Return the ec2 instances given the interface id.

    Return the ec2 instance given the interfaceß id, if instance id does not
    exist, then return false for unknown interface.

    """
    ec2 = boto3.resource('ec2')
    instance = False
    try:
        network_interface = ec2.NetworkInterface(eniId)
        instance = network_interface.attachment['InstanceId']
    except(ex):
        logger.info("Interface: {} is unknown".format(eniId))
    return instance


def parseEvent(event):
    """Return parsed events from cloudwatch."""
    # get CloudWatch logs
    data = str(event['awslogs']['data'])
    # decode and uncompress CloudWatch logs
    logs = gzip.GzipFile(fileobj=StringIO(
            data.decode('base64', 'strict'))).read()
    # convert the log data from JSON into a dictionary
    return json.loads(logs)


def isIpException(dstaddr, dstport):
    """Return boolean if IP Address is in the exceptions list."""
    for exception in exceptions:
        if ((IPAddress(dstaddr) in IPNetwork(exception['cidr'])) and
                (dstport == exception['port'])):
            msg = "Allowed within exception cidr {} and port{}".format(
                    exception['cidr'], exceptoin['port'])
            logging.info(msg)
            return True
    return False


def addAWSExceptions():
    """Add AWS Managed Service IP Addresses to exceptions."""
    logger.info("Adding AWS endpoints to exceptions list.")

    # Gets and parses AWS IP Addresses into JSON object.
    data = urllib2.urlopen(aws_data_source_url)
    ipRanges = json.load(data)

    # Loops through all IP Addresses and creates a hash and adds to exceptions.
    for range in ipRanges['prefixes']:
        if range['service'] == aws_service:
            for port in aws_ports:
                part = {}
                part['cidr'] = range['ip_prefix']
                part['port'] = port
                exceptions.append(part)


def getInstanceById(instanceId):
    """Return ec2 instance by instance id."""
    try:
        ec2 = boto3.resource('ec2')
        instance = ec2.Instance(instanceId)
    except(ex):
        raise Exception("Unable to find instance. {}".format(instanceId))


def stopInstance(instance):
    """Stop ec2 instance given the ec2 object."""
    logging.info("Sending stop message to instance. {}".format(instanceId))
    try:
        response = instance.stop(
            DryRun=dryrun,
            Force=True
        )
    except(ex):
        raise Exception("Unable to stop instance. {}".format(instanceId))


def snapshotVolumeById(volumeId, instanceId):
    """Create a snapshot of a volume by volume id."""
    try:
        ec2 = boto3.resource('ec2')
        volume = ec2.Volume(volumeId)
    except(ex):
        Exception("Unable to find volume {} to snapshot".format(volumeId))

    desc = "Snapshot for instance {} made by the instanceKiller."
    snapshot = volume.create_snapshot(
        DryRun=dryrun,
        Description=desc.format(instanceId)
    )

    return snapshot.id


def snapshotInstance(instance):
    """Create a snapshot of every volume inside an instance."""
    volume_iterator = instance.volumes.all()
    for volume in volume_iterator:
        try:
            snapshot = snapshotVolumeById(volume.id, instanceId)
            logging.info("Snapshot for instance {} volume {} snapshot {}"
                         .format(instanceId, volume.id, snapshot))
        except(ex):
            logging.warning(ex.msg)


def killInstance(instanceId):
    logging.info("Killing instance".format(instanceId))
    instance = getInstanceById(instanceId)
    stopInstance(instance)
    snapshotInstance(instance)
    logging.info(Sending terminate message to instance. {}".format(instanceId))
    try:
        response = instance.terminate(DryRun=dryrun)
    except(ex):
        raise Exception("Unable to terminate instance to kill. {}"
                        .format(instanceId))

    sendNotification(instanceId, snapshot)


def sendNotification(instanceId, snapshotId):
    """Send a notification that an instance has been terminated."""
    client = boto3.client('sns')
    msg = "Instance {} has been terminated.  Snapshot {} created."
    try:
        response = client.publish(
            TopicArn=snsArn,
            Message=msg.format(instanceId, snapshotId)
            Subject='InstanceKiller has terminated an instance'
        )
        logging.info("SNS Notification sent.")
    except(ex):
        logging.error("Unable to send SNS notification.")


def lambda_handler(event, context):
    """Main entrypoint for lambda function.

    Loops through VPC Flow Log event, parses and validates if the server has
    been compromised.

    """

    # Print out the event, helps with debugging
    print(event)

    events = parseEvent(event)

    if allowAWS:
        addAWSExceptions()

    killList = set()
    unknownInterfaces = []

    for record in events['logEvents']:

        try:
            extractedFields = record['extractedFields']
        except(ex):
            raise Exception("Could not find 'extractedFields' is the " +
                            "CloudWatch feed set correctly?")

        instanceId = getInstanceIdByInterfaceId(
            extractedFields['interface_id'])

        if instanceId:
            instaneInfo = "Instance:{}\t Interface:{}\t SrcAddr:{}\t " +
            "DstAddr:{}\t DstPort:{}\t"
            logging.info(instanceInfo.format(
                    instanceId,
                    extractedFields['interface_id'],
                    extractedFields['srcaddr'],
                    extractedFields['dstaddr'],
                    extractedFields['dstport']
            ))

            if isIpException(extractedFields['dstaddr'],
                             extractedFields['dstport']):
                logging.info("OK")
            else:
                logging.info("ALERT!! Disallowed traffic {}", instanceInfo)
                killList.add(instanceId)

        else:
            unknownInterfaces.append(extractedFields['interface_id'])

    logging.info("There are {} instances on the kill list!".format(
            len(killlist)))

    if len(unknownInterfaces):
        logging.info("Found {} interfaces not attached to instances "
                     + "(probably an ELB).".format(len(unknownInterfaces)))
        logging.info("Interfaces without instances:{}".format(
                unknownInterfaces))

    killed = 0

    for instanceId in killList:
        try:
            killInstance(instanceId)
            killed += 1
        except(ex):
            logging.error(ex.msg)

    return ("Killed {} instances.".format(killed))
