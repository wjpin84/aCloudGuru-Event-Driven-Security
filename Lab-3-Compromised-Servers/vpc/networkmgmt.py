"""Class that represents what is not allowed to access the network."""

import logger
import json
import urllib2
from netaddr import IPNetwork, IPAddress


class NetworkMgmt():

    def __init__(self):
        """Set default construtor."""
        self.__exceptions = []

    def addException(self, networkAddress):
        """Add network address to exception list."""
        self._exceptions.append(networkAddress)

    def addExceptions(self, networkAddressList):
        """Add a list of network addresses to exception list."""
        self._exceptions.extend(networkAddressList)

    def contains(self, location, port):
        """Return boolean if network address is an exception."""
        contains = false
        for exception in __exceptions:
            if exception.contains(location, port):
                contains = true
        return contains


class NetworkMgmtUtility():

    """Utility class to retrieve Network Addresses from AWS."""

    def getAwsWhiteList(url, service, port):
        """Return AWS Managed Service IP Addresses to exceptions."""
        logger.info("Adding AWS endpoints to exceptions list.")
        exceptions = []

        # Gets and parses AWS IP Addresses into JSON object.
        data = urllib2.urlopen(url)
        ipRanges = json.load(data)

        # Loops through list and creates a list of NetworkAddresses.
        for range in ipRanges['prefixes']:
            if range['service'] == service:
                for port in ports:
                    exceptions.append(NetworkAddress(range['ip_prefix'], port))
        return exceptions


class NetworkAddress():

    """Domain object for network address."""

    def __init__(self, cidr, port):
        """Set constructor to setting the network address."""
        self.__cidr = cidr
        self.__port = port

    def getCidr(self):
        """Return location of Network Address."""
        return self.__cidr

    def getPort(self):
        """Return port of Network Address."""
        return self.__port

    def contains(self, location, port):
        """Return boolean if address and port are found in the cidr range."""
        found = False
        if ((IPAddress(location) in IPNetwork(self.__cidr)) and
                (port == self.__port')):
            found = True
        return found
