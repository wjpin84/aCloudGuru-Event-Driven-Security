# InstanceKiller

M.Chambers 2016

Please understand that I do not support this code, and neither does anyone else. Sorry.

You should never install anything in an AWS account that is not supported (i.e. written and support by you, verified and supported by you, or under a 3rd party support arrangement).  To verify a 'thing' you could absolutely install it in an isolated test environment, but even then under a watchful eye, especially if the 'thing' is going to incur costs.

## aCloud.Guru

This file was created for the purposes of the Event Based Security course from aCloud.Guru

## What is it?
A Lambda function designed to detect a security event when an EC2 instance initiates a connection to the Internet.

## What does it do?
When a compromised server has been detected, a snapshot is made of the instances volumes, and then the instance is terminated.

##IMPORTANT
These files are distributed on an AS IS BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
