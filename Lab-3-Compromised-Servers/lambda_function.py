#! /usr/bin/python
"""Lambda for Shutting down compromised servers.

AWS Lambda function is to support event-driven security based on evaluating.
the VPC Flow Logs to see if any EC2 instances have been compromised.  In the
event of a compromise will send a SNS notification to shutdown the EC2 instance
that will be set to start a fresh instance.

"""

import os
import yaml
import logging
from vpc.event import VpcEvent, VpcEventUtility
from vpc.networkmgmt import NetworkAddress, NetworkMgmt, NetworkMgmtUtility

# User variables
network_exceptions = [NetworkAddress("0.0.0.0/0", "123")]
aws_data_source_url = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
aws_service = "AMAZON"
aws_ports = ["80", "443"]
dryrun = False
allowAWS = True


def lambda_handler(event, context):
    """Main entrypoint for lambda function.

    Loops through VPC Flow Log event, parses and validates if the server has
    been compromised.

    """

    # Setup logging for the application based on the logging.yaml file.
    setup_logging()

    # Build whitelist for network security
    networkWhiteList = NetworkMgmt()
    networkWhiteList.addExceptions(network_exceptions)
    if allowAWS:
        networkWhiteList.addExceptions(
                NetworkMgmtUtility.getAwsWhiteList(aws_data_source_url,
                                                   aws_service, aws_ports))

    # Filter events into kill and unknown lists.
    records = sortLoggedEvents(event, networkWhiteList)
    logging.info("There are {} instances on the kill list!".format(
            len(records['kill'])))

    # Process unknown and kill events.
    processUnknownInterfaces(records['unknown'])
    killInstances(records['kill'])


def setup_logging(default_path='logging.yaml', default_level=logging.INFO,
                  env_key='LOG_CFG'):
    """Setup logging configuration"""
    path = default_path
    value = os.getenv(env_key, None)
    if value:
        path = value
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = yaml.safe_load(f.read())
        logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=default_level)


def sortLoggedEvents(event, whitelist):
    """Return a dictionary of events needing processed (kill & unknown)."""
    records = {'kill' = [], 'unknown' = []}

    for record in VpcEventUtility.parseEvent(event)['logEvents']:
        # Parse record into VpcEvent object.
        if 'extractedFields' not in record continue
        vpcEvent = VpcEvent(record)

        # Retrieve instance identifer from AWS
        instanceId = VpcEventUtility.getInstanceIdByInterfaceId(interfaceId)
        vpcEvent.setInstanceId(instanceId)

        # Filter object based on unknown or kill
        logging.info(vpcEvent.toString())
        if vpcEvent.isUnknown:
            # if no instance id
            records['unknown'].append(vpcEvent)
        else if not whitelist.contains(
                    vpcEvent.getDestination()['addr'],
                vpcEvent.getDestination()['port']):
            # if not in the whitelist, put in kill list.
            records['kill'].append(vpcEvent)
    return records


def processUnknownInterfaces(unknownInterfaces):
    """Process unknown interfaces."""
    if len(unknownInterfaces):
        logging.info("Found {} interfaces not attached to instances "
                     + "(probably an ELB).".format(len(unknownInterfaces)))
        logging.info("Interfaces without instances:{}".format(
                unknownInterfaces))


def killInstances(killList):
    """Kill instances that are compromised."""
    killed = 0
    for vpcEvent in killList:
        try:
            VpcEventUtility.killInstance(vpcEvent)
            killed += 1
        except(ex):
            logging.error(ex.msg)

    logging.info("Killed {} instances.".format(killed))
