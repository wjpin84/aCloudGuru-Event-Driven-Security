# iam-event-lambda

M.Chambers 2016

Please understand that I do not support this code, and neither does anyone else. Sorry.

You should never install anything in an AWS account that is not supported (i.e. written and support by you, verified and supported by you, or under a 3rd party support arrangement).  To verify a 'thing' you could absolutely install it in an isolated test environment, but even then under a watchful eye, especially if the 'thing' is going to incur costs.

## aCloud.Guru

This file was created for the purposes of the Event Based Security course from aCloud.Guru

## What is it?
An Example AWS CloudFormation template that creates an Lambda function written to revoke access to IAM APIs for anyone outside of a particular IAM Group.

## What is created?
The main objects created by this template are:
- IAM Policies
- Lambda function

## How to use
Create a stack using the template.  Everything, including the Lambda function is included.   

##IMPORTANT
These files are distributed on an AS IS BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
