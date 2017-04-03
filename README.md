audit S3
============================
This stack will monitor S3 and alert on things CloudCoreo developers think are violations of best practices


## Description
This repo is designed to work with CloudCoreo. It will monitor S3 against best practices for you and send a report to the email address designated by the config.yaml AUDIT&#95;AWS&#95;S3&#95;ALERT&#95;RECIPIENT value


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-s3/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

**None**


## Required variables with default

### `AUDIT_AWS_S3_ALLOW_EMPTY`:
  * description: Would you like to receive empty reports? Options - true / false. Default is false.
  * default: false

### `AUDIT_AWS_S3_SEND_ON`:
  * description: Send reports always or only when there is a change? Options - always / change. Default is change.
  * default: change

### `AUDIT_AWS_S3_REGIONS`:
  * description: List of AWS regions to check. Default is all regions. Choices are us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,ap-south-1,ap-northeast-2,ap-southeast-1,ap-southeast-2,ap-northeast-1,eu-central-1,eu-west-1,eu-west-1,sa-east-1
  * default: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, ap-south-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-northeast-1, eu-central-1, eu-west-1, eu-west-2, sa-east-1


## Optional variables with default

### `AUDIT_AWS_S3_ALERT_LIST`:
  * description: Which alerts would you like to check for? Default is all S3 alerts. Choices are s3-allusers-write,s3-allusers-write-acp,s3-allusers-read,s3-authenticatedusers-write,s3-authenticatedusers-write-acp,s3-authenticatedusers-read,s3-logging-disabled,s3-world-open-policy-delete,s3-world-open-policy-get,s3-world-open-policy-list,s3-world-open-policy-put,s3-world-open-policy-all,s3-only-ip-based-policy
  * default: s3-allusers-write, s3-allusers-write-acp, s3-allusers-read, s3-authenticatedusers-write, s3-authenticatedusers-write-acp, s3-authenticatedusers-read, s3-logging-disabled, s3-world-open-policy-delete, s3-world-open-policy-get, s3-world-open-policy-list, s3-world-open-policy-put, s3-world-open-policy-all, s3-only-ip-based-policy

### `AUDIT_AWS_S3_OWNER_TAG`:
  * description: Enter an AWS tag whose value is an email address of the owner of the S3 object. (Optional)
  * default: NOT_A_TAG


## Optional variables with no default

### `AUDIT_AWS_S3_ALERT_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifiers. If more than one, separate each with a comma.

## Tags
1. Audit
1. Best Practices
1. Alert
1. S3

## Categories
1. Audit



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-s3/master/images/diagram.png "diagram")


## Icon
![icon](https://raw.githubusercontent.com/CloudCoreo/audit-aws-s3/master/images/icon.png "icon")

