---
title:  "CloudGoat Vulnerable Lambda Scenario - Part 2 (Response)"
description: > 
    As an incident responder, walk through how we can investigate and resolve an
    ongoing attack targeting CloudGoat's vulnerable Lambda scenario.
date: 2023-03-28 14:46:58-04:00
categories: [Cloud, AWS] 
tags: [aws, cloud, lab, walkthrough, lambda, response]
toc: true
---

* [Part 1](https://0xdeadbeefjerky.com/posts/cloudgoat-lambda-walkthrough/) - 
Attacking CloudGoat's vulnerable Lambda scenario
* Part 2 (you are here) - Responding to the attack

![cloudgoat](/assets/img/responders.png){: .center-image}

In [part one](https://0xdeadbeefjerky.com/posts/cloudgoat-lambda-walkthrough/) 
of this series, we walked through the steps necessary to exploit a Lambda 
function with an inherent SQL injection vulnerability, escalate our privileges 
and subsequently access company secrets. In this post (part two), we'll assume 
the role of a responder (e.g., SOC analyst, IR team member) and conduct an 
investigation with the goal of evicting the attacker from the affected AWS 
environment.

## The Initial Alert

The starting point that triggers our investigation would be entirely dependent 
on the security tooling being used by the organization. For the sake of example,
we'll only rely on services, tooling and telemetry that are native to AWS to 
facilitate the investigation and "mock" the initial alert.

Here's a quick recap of the attack we executed in the first post:
* **Discovery**: Gained some situational awareness by exploring the affected IAM
user's permissions and enumerating available resources within the AWS account
* **Privilege Escalation**: Exploited a reachable Lambda function with an 
inherent SQL injection vulnerability to attach the `AdministratorAccess` managed
policy to the affected IAM user
* **Collection**: Leveraged the newly minted access to retrieve secrets from 
Secrets Manager

Let's assume the worst case scenario, in which the initial alert points to a 
user accessing the `final_flag` secret from a suspicious IP address (one that 
isn't owned/managed by the organization or hasn't been previously observed). 
This could be in the form of a [GuardDuty IAM finding](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#credentialaccess-iam-anomalousbehavior),
a custom detection, an alert from a third-party solution, etc. In any case, this
is what we're given:  

> The secret "vulnerable_lambda_cgid13u1qpdipe-final_flag" was accessed using 
> AWS Secrets Manager by a suspicious IP address (1.2.3.4) at 
> 2023-03-28T17:18:59Z.
{: .prompt-danger }

## Building Context

A responder's ability to quickly and effectively investigate an incident is 
almost entirely dependent on the context that's made available to them. In this 
example, the context is quite limited (intentionally), so we're left to build 
out the necessary context on our own.

### Analyze Cloudtrail Logs Using Athena

We know that a secret within AWS Secrets Manager was accessed from a suspicious 
IP. Let's pivot on the secret ID in question by pulling the relevant CloudTrail 
logs - events with an event name of `GetSecretValue` further filtered on both 
the secret ID (`CloudTrailEvent:requestParameters:secretId`) and the source IP
address. There are many options to sift through and analyze CloudTrail data, 
such as piping output from the AWS CLI to a utility such as `jq`, using the 
Python SDK and storing the output as a Pandas DataFrame (ideally, [using a Jupyter notebook](https://catalog.workshops.aws/incident-response-jupyter/en-US)), 
etc. Because we're dedicated to the theme of using native AWS services and 
tooling when possible, we'll [query CloudTrail logs using Athena](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html) 
for this purpose.

Execute the following bash script by passing the necessary arguments.

```bash
# setup-investigation.sh
#!/bin/bash

# Example: 
# ./setup-investigation.sh -r us-east-1 -b example-bucket-123 \
#   -w test-workgroup -o example-athena-output-bucket-456 -d "this is a test" \
#   -n cloudtrail_logs_test -t "2023/03/01"

# Parse command-line arguments
while getopts ":r:b:w:o:d:n:t:" opt; do
  case ${opt} in
    r) AWS_REGION=$OPTARG;;
    b) S3_BUCKET_NAME=$OPTARG;;
    w) ATHENA_WORKGROUP_NAME=$OPTARG;;
    o) ATHENA_OUTPUT_LOCATION=$OPTARG;;
    d) ATHENA_WORKGROUP_DESCRIPTION=$OPTARG;;
    n) ATHENA_TABLE_NAME=$OPTARG;;
    t) START_TIMESTAMP=$OPTARG;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# Check if all required arguments are provided
if [ -z "$AWS_REGION" ] || [ -z "$S3_BUCKET_NAME" ] || [ -z "$ATHENA_WORKGROUP_NAME" ] || [ -z "$ATHENA_OUTPUT_LOCATION" ] || [ -z "$ATHENA_WORKGROUP_DESCRIPTION" ] || [ -z "$START_TIMESTAMP" ] || [ -z "$ATHENA_TABLE_NAME" ]; then
  echo "Usage: $0 -r <AWS_REGION> -b <S3_BUCKET_NAME> -w <ATHENA_WORKGROUP_NAME> -o <ATHENA_OUTPUT_LOCATION> -t <START_TIMESTAMP> -d <ATHENA_WORKGROUP_DESCRIPTION> -n <ATHENA_TABLE_NAME>"
  exit 1
fi

# Fetch current AWS account ID
ACCOUNT_ID=`aws sts get-caller-identity --query 'Account' --output text`

CREATE_TABLE_QUERY=$(cat <<EOF
  CREATE EXTERNAL TABLE $ATHENA_TABLE_NAME(
    eventVersion STRING,
    userIdentity STRUCT<
        type: STRING,
        principalId: STRING,
        arn: STRING,
        accountId: STRING,
        invokedBy: STRING,
        accessKeyId: STRING,
        userName: STRING,
        sessionContext: STRUCT<
            attributes: STRUCT<
                mfaAuthenticated: STRING,
                creationDate: STRING>,
            sessionIssuer: STRUCT<
                type: STRING,
                principalId: STRING,
                arn: STRING,
                accountId: STRING,
                userName: STRING>,
            ec2RoleDelivery:string,
            webIdFederationData:map<string,string>
        >
    >,
    eventTime STRING,
    eventSource STRING,
    eventName STRING,
    awsRegion STRING,
    sourceIpAddress STRING,
    userAgent STRING,
    errorCode STRING,
    errorMessage STRING,
    requestparameters STRING,
    responseelements STRING,
    additionaleventdata STRING,
    requestId STRING,
    eventId STRING,
    readOnly STRING,
    resources ARRAY<STRUCT<
        arn: STRING,
        accountId: STRING,
        type: STRING>>,
    eventType STRING,
    apiVersion STRING,
    recipientAccountId STRING,
    serviceEventDetails STRING,
    sharedEventID STRING,
    vpcendpointid STRING,
    tlsDetails struct<
        tlsVersion:string,
        cipherSuite:string,
        clientProvidedHostHeader:string>
  )
  PARTITIONED BY (
    \`timestamp\` string)
  ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
  STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
  OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
  LOCATION
    's3://$S3_BUCKET_NAME/AWSLogs/$ACCOUNT_ID/CloudTrail/$AWS_REGION'
  TBLPROPERTIES (
    'projection.enabled'='true', 
    'projection.timestamp.format'='yyyy/MM/dd', 
    'projection.timestamp.interval'='1', 
    'projection.timestamp.interval.unit'='DAYS', 
    'projection.timestamp.range'='$START_TIMESTAMP,NOW', 
    'projection.timestamp.type'='date', 
    'storage.location.template'='s3://$S3_BUCKET_NAME/AWSLogs/$ACCOUNT_ID/CloudTrail/$AWS_REGION/\${timestamp}')
EOF
)

# Create Athena workgroup
echo "Creating Athena workgroup..."
aws athena create-work-group \
  --region $AWS_REGION \
  --name $ATHENA_WORKGROUP_NAME \
  --description "$ATHENA_WORKGROUP_DESCRIPTION" \
  --output json

if [ $? -eq 0 ]; then
    echo "Athena workgroup $ATHENA_WORKGROUP_NAME created!"
fi 

# Create partitioned Athena table
echo "Creating Athena table..."
aws athena start-query-execution \
  --region $AWS_REGION \
  --query-string "$CREATE_TABLE_QUERY" \
  --result-configuration "OutputLocation=s3://$ATHENA_OUTPUT_LOCATION"

if [ $? -eq 0 ]; then
    echo "Athena table created successfully!"
fi
```

> **NOTE:** The CloudTrail "Event history" section in the console has a "Create 
> Athena table" option. However, the resulting query doesn't account for 
> partitioning, which may unnecessarily increase query costs, depending on the 
> size of the trail being imported to Athena.
{: .prompt-info }

Now, we can begin our investigation! Navigate to Athena in the AWS console, open
up a new tab within the query editor, choose the newly created workgroup using 
the dropdown in the top-right and locate the initial CloudTrail event that 
likely produced the alert:    

```sql
select eventtime, useridentity, eventsource, eventname, awsregion, sourceipaddress, useragent, requestparameters, tlsdetails
from cloudtrail_logs_pp
where eventname = 'GetSecretValue'
and timestamp = '2023/03/28'
and sourceipaddress = '1.2.3.4'
and json_extract_scalar(requestparameters, '$.secretId') = 'vulnerable_lambda_cgid13u1qpdipe-final_flag'
```

Review the results, with specific focus on the `useridentity` attribute:  

| eventtime |	useridentity |	eventsource |	eventname |	awsregion |	sourceipaddress |	useragent |	requestparameters |	tlsdetails |
|--------------|--------------|-------------|-------------|-----------|-----------------|-------------|-------------------|------------|
| 2023-03-28T17:18:59Z | {type=IAMUser, principalid=AIDAREDACTED, arn=arn:aws:iam::REDACTED:user/cg-bilbo-vulnerable_lambda_cgid13u1qpdipe, accountid=REDACTED, invokedby=null, accesskeyid=AKIAREDACTED, username=cg-bilbo-vulnerable_lambda_cgid13u1qpdipe, sessioncontext=null} |	secretsmanager.amazonaws.com |	GetSecretValue	| us-east-1 |	1.2.3.4 |	aws-cli/2.9.1 Python/3.9.11 Linux/5.15.90.1-microsoft-standard-WSL2 exe/x86_64.ubuntu.22 prompt/off command/secretsmanager.get-secret-value	| {"secretId":"vulnerable_lambda_cgid13u1qpdipe-final_flag"}	| {tlsversion=TLSv1.2, ciphersuite=ECDHE-RSA-AES128-GCM-SHA256, clientprovidedhostheader=secretsmanager.us-east-1.amazonaws.com} |

We've discovered the offending principal is an IAM user prepended with 
"cg-bilbo". Let's determine what else this particular user has done from the 
provided IP address by pivoting on the corresponding access key:  

```sql
select eventtime, sourceipaddress, useridentity.username, eventsource, eventname
from cloudtrail_logs_pp
where useridentity.accesskeyid = 'AKIAREDACTED'
and sourceipaddress = '1.2.3.4'
order by eventtime
```

| eventtime |	sourceipaddress	| username |	eventsource |	eventname |
|-----------|-------------------|----------|----------------|-------------|
| 2023-03-28T17:00:57Z |	1.2.3.4 |	cg-bilbo-vulnerable_lambda_cgid13u1qpdipe	| iam.amazonaws.com |	ListAccountAliases |
| 2023-03-28T17:01:44Z |	1.2.3.4 |	cg-bilbo-vulnerable_lambda_cgid13u1qpdipe	| iam.amazonaws.com |	ListGroupsForUser |
| 2023-03-28T17:01:56Z |	1.2.3.4 |	cg-bilbo-vulnerable_lambda_cgid13u1qpdipe	| iam.amazonaws.com |	ListAttachedUserPolicies |
| 2023-03-28T17:02:05Z |	1.2.3.4 |	cg-bilbo-vulnerable_lambda_cgid13u1qpdipe	| iam.amazonaws.com |	ListUserPolicies |
| 2023-03-28T17:02:28Z |	1.2.3.4 |	cg-bilbo-vulnerable_lambda_cgid13u1qpdipe	| iam.amazonaws.com |	GetUserPolicy |
| 2023-03-28T17:02:37Z |	1.2.3.4 |	cg-bilbo-vulnerable_lambda_cgid13u1qpdipe	| iam.amazonaws.com |	ListRoles |
| 2023-03-28T17:02:46Z |	1.2.3.4 |	cg-bilbo-vulnerable_lambda_cgid13u1qpdipe	| iam.amazonaws.com |	ListRolePolicies |
| 2023-03-28T17:02:56Z |	1.2.3.4 |	cg-bilbo-vulnerable_lambda_cgid13u1qpdipe	| iam.amazonaws.com |	GetRolePolicy |
| 2023-03-28T17:03:39Z |	1.2.3.4 |	cg-bilbo-vulnerable_lambda_cgid13u1qpdipe	| sts.amazonaws.com |	AssumeRole |
| 2023-03-28T17:03:55Z |	1.2.3.4 |	cg-bilbo-vulnerable_lambda_cgid13u1qpdipe	| sts.amazonaws.com |	AssumeRole |
| 2023-03-28T17:05:56Z |	1.2.3.4 |	cg-bilbo-vulnerable_lambda_cgid13u1qpdipe	| sts.amazonaws.com |	AssumeRole |
| 2023-03-28T17:07:23Z |	1.2.3.4 |	cg-bilbo-vulnerable_lambda_cgid13u1qpdipe	| sts.amazonaws.com |	AssumeRole |
| 2023-03-28T17:18:08Z |	1.2.3.4 |	cg-bilbo-vulnerable_lambda_cgid13u1qpdipe	| iam.amazonaws.com |	ListAttachedUserPolicies |
| 2023-03-28T17:18:25Z |	1.2.3.4 |	cg-bilbo-vulnerable_lambda_cgid13u1qpdipe	| iam.amazonaws.com |	ListAttachedUserPolicies |
| 2023-03-28T17:18:38Z |	1.2.3.4 |	cg-bilbo-vulnerable_lambda_cgid13u1qpdipe	| secretsmanager.amazonaws.com |	ListSecrets |
| 2023-03-28T17:18:59Z |	1.2.3.4 |	cg-bilbo-vulnerable_lambda_cgid13u1qpdipe	| secretsmanager.amazonaws.com |	GetSecretValue |

The initial set of API calls leading up to the call to `AssumeRole` is 
interesting, as those calls appear to be potential reconnaissance (series of 
`Get*` and `List*` requests). To confirm this suspicion, let's dig into the 
request parameters. It'd be quite strange for a legitimate user to issue a 
flurry of queries trying to determine what permissions they had, no?

```sql
select eventtime, eventname, requestparameters, responseelements
from cloudtrail_logs_pp
where useridentity.accesskeyid = 'AKIAREDACTED'
and sourceipaddress = '1.2.3.4'
order by eventtime
```

| eventtime |	eventname |	requestparameters |	responseelements |
|-----------|-------------|-------------------|------------------|
| 2023-03-28T17:00:57Z |	ListAccountAliases | | |	
| 2023-03-28T17:01:44Z |	ListGroupsForUser |	{"userName":"cg-bilbo-vulnerable_lambda_cgid13u1qpdipe"} | |
| 2023-03-28T17:01:56Z |	ListAttachedUserPolicies |	{"userName":"cg-bilbo-vulnerable_lambda_cgid13u1qpdipe"} | |	
| 2023-03-28T17:02:05Z |	ListUserPolicies |	{"userName":"cg-bilbo-vulnerable_lambda_cgid13u1qpdipe"} | |	
| 2023-03-28T17:02:28Z |	GetUserPolicy |	{"userName":"cg-bilbo-vulnerable_lambda_cgid13u1qpdipe","policyName":"cg-bilbo-vulnerable_lambda_cgid13u1qpdipe-standard-user-assumer"}	| |
| 2023-03-28T17:02:37Z |	ListRoles | | |
| 2023-03-28T17:02:46Z |	ListRolePolicies |	{"roleName":"cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe"} | |
| 2023-03-28T17:02:56Z |	GetRolePolicy |	{"policyName":"lambda-invoker","roleName":"cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe"}	| |
| 2023-03-28T17:03:39Z |	AssumeRole |	{"roleArn":"arn:aws:iam::REDACTED:role/cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe","roleSessionName":"1680023021100268365","durationSeconds":3600} |	{"credentials":{"accessKeyId":"ASIAREDACTED","sessionToken":"REDACTED","expiration":"Mar 28, 2023, 6:03:39 PM"},"assumedRoleUser":{"assumedRoleId":"AROAREDACTED:1680023021100268365","arn":"arn:aws:sts::REDACTED:assumed-role/cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe/1680023021100268365"}} |
| 2023-03-28T17:03:55Z |	AssumeRole |	{"roleArn":"arn:aws:iam::REDACTED:role/cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe","roleSessionName":"1680023036636263280","durationSeconds":3600} |	{"credentials":{"accessKeyId":"ASIAREDACTED","sessionToken":"REDACTED","expiration":"Mar 28, 2023, 6:03:55 PM"},"assumedRoleUser":{"assumedRoleId":"AROAREDACTED:1680023036636263280","arn":"arn:aws:sts::REDACTED:assumed-role/cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe/1680023036636263280"}} |
| 2023-03-28T17:05:56Z |	AssumeRole |	{"roleArn":"arn:aws:iam::REDACTED:role/cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe","roleSessionName":"1680023157475147111","durationSeconds":3600} |	{"credentials":{"accessKeyId":"ASIAREDACTED","sessionToken":"REDACTED","expiration":"Mar 28, 2023, 6:05:56 PM"},"assumedRoleUser":{"assumedRoleId":"AROAREDACTED:1680023157475147111","arn":"arn:aws:sts::REDACTED:assumed-role/cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe/1680023157475147111"}} |
| 2023-03-28T17:07:23Z |	AssumeRole |	{"roleArn":"arn:aws:iam::REDACTED:role/cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe","roleSessionName":"1680023244813312140","durationSeconds":3600} |	{"credentials":{"accessKeyId":"ASIAREDACTED","sessionToken":"REDACTED","expiration":"Mar 28, 2023, 6:07:23 PM"},"assumedRoleUser":{"assumedRoleId":"AROAREDACTED:1680023244813312140","arn":"arn:aws:sts::REDACTED:assumed-role/cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe/1680023244813312140"}} |
| 2023-03-28T17:18:08Z |	ListAttachedUserPolicies |	{"userName":"cg-bilbo-"} | |
| 2023-03-28T17:18:25Z |	ListAttachedUserPolicies |	{"userName":"cg-bilbo-vulnerable_lambda_cgid13u1qpdipe"} | |	
| 2023-03-28T17:18:38Z |	ListSecrets | | |
| 2023-03-28T17:18:59Z |	GetSecretValue | {"secretId":"vulnerable_lambda_cgid13u1qpdipe-final_flag"}	| |

Shockingly, our suspicion was correct! According to the `requestparameters`, the
user was targeting the very IAM user they used to issue the request. This is a 
very common form of discovery (more specifically, situational awareness) when a 
cloud account has been compromised. Let's determine which IAM roles the user was
able to assume, and what subsequent actions they were able to perform using that
role.

```sql
select eventtime, eventname, requestparameters, responseelements
from cloudtrail_logs_pp
where useridentity.accesskeyid = 'AKIAREDACTED'
and sourceipaddress = '1.2.3.4'
and eventname = 'AssumeRole'
order by eventtime
```

| eventtime	| eventname	| requestparameters	| responseelements |
|-----------|-----------|-------------------|------------------|
| 2023-03-28T17:03:39Z |	AssumeRole |	{"roleArn":"arn:aws:iam::REDACTED:role/cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe","roleSessionName":"1680023021100268365","durationSeconds":3600}	| {"credentials":{"accessKeyId":"ASIAREDACTED","sessionToken":"REDACTED","expiration":"Mar 28, 2023, 6:03:39 PM"},"assumedRoleUser":{"assumedRoleId":"AROAREDACTED:1680023021100268365","arn":"arn:aws:sts::REDACTED:assumed-role/cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe/1680023021100268365"}} |
| 2023-03-28T17:03:55Z |	AssumeRole |	{"roleArn":"arn:aws:iam::REDACTED:role/cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe","roleSessionName":"1680023036636263280","durationSeconds":3600}	| {"credentials":{"accessKeyId":"ASIAREDACTED","sessionToken":"REDACTED","expiration":"Mar 28, 2023, 6:03:55 PM"},"assumedRoleUser":{"assumedRoleId":"AROAREDACTED:1680023036636263280","arn":"arn:aws:sts::REDACTED:assumed-role/cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe/1680023036636263280"}} |
| 2023-03-28T17:05:56Z |	AssumeRole |	{"roleArn":"arn:aws:iam::REDACTED:role/cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe","roleSessionName":"1680023157475147111","durationSeconds":3600}	| {"credentials":{"accessKeyId":"ASIAREDACTED","sessionToken":"REDACTED","expiration":"Mar 28, 2023, 6:05:56 PM"},"assumedRoleUser":{"assumedRoleId":"AROAREDACTED:1680023157475147111","arn":"arn:aws:sts::REDACTED:assumed-role/cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe/1680023157475147111"}} |
| 2023-03-28T17:07:23Z |	AssumeRole |	{"roleArn":"arn:aws:iam::REDACTED:role/cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe","roleSessionName":"1680023244813312140","durationSeconds":3600}	| {"credentials":{"accessKeyId":"ASIAREDACTED","sessionToken":"REDACTED","expiration":"Mar 28, 2023, 6:07:23 PM"},"assumedRoleUser":{"assumedRoleId":"AROAREDACTED:1680023244813312140","arn":"arn:aws:sts::REDACTED:assumed-role/cg-lambda-invoker-vulnerable_lambda_cgid13u1qpdipe/1680023244813312140"}} |

The `AssumeRole` operation leverages the STS service to generate a temporary set 
of credentials with the same permissions as the target role to be assumed. We 
can further pivot on these access keys (starting with 'ASIA') to identify the 
subsequent activity carried out using these temporary credentials.  

```sql
select eventtime, useridentity, eventsource, eventname, requestparameters, responseelements 
from cloudtrail_logs_pp
where useridentity.accesskeyid in ('ASIAREDACTED', 'ASIAREDACTED',  'ASIAREDACTED', 'ASIAREDACTED')
and sourceipaddress = '1.2.3.4'
order by eventtime
```

| eventtime |	useridentity |	eventsource |	eventname |	requestparameters |	responseelements |
|-----------|--------------|--------------|-----------|-------------------|------------------|
| 2023-03-28T17:03:55Z |	ASIAREDACTED |	lambda.amazonaws.com |	ListFunctions20150331 |		|
| 2023-03-28T17:05:56Z |	ASIAREDACTED |	lambda.amazonaws.com |	GetFunction20150331v2 |	{"functionName":"vulnerable_lambda_cgid13u1qpdipe-policy_applier_lambda1"}	|
| 2023-03-28T17:07:25Z |	ASIAREDACTED |	lambda.amazonaws.com |	Invoke |		|

### Investigate Lambda Function Logs Using CloudWatch

It appears the attacker listed the available Lambda functions and used the call
to `GetFunctions` to pull more detailed information about the 
`vulnerable_lambda_cgid13u1qpdipe-policy_applier_lambda1` Lambda function, which
includes a direct link to the actual function code. Although CloudTrail doesn't 
log the specifics of the function invocation, we can tap into the associated 
CloudWatch log group (which is automatically created along with the Lambda 
function) to achieve this.  

1. Navigate to CloudWatch in the console

2. Choose Logs > Log groups

3. Select the appropriate log group (e.g., `/aws/lambda/my-function`). In this 
case, `/aws/lambda/vulnerable_lambda_cgid13u1qpdipe-policy_applier_lambda1`.

4. Multiple log streams may exist. Be sure to choose the stream that contains 
logs covering the same time frame as the call to `Invoke` noted in the 
CloudTrail events (in this case, 2023-03-28T17:07:25Z)

| timestamp | message |
|-----------|---------|
| 1680023244380 | "INIT_START Runtime Version: python:3.9.v18	Runtime Version ARN: arn:aws:lambda:us-east-1::runtime:edb5a058bfa782cb9cedc6d534ac8b8c193bc28e9a9879d9f5ebaaf619cd0fc0 |
| 1680023244888 | "START RequestId: 4439301b-290c-4ae5-811b-228bb60418c2 Version: $LATEST |
| 1680023244889 | "target policys are : [""AdministratorAccess'; --""] |
| 1680023244889 | "applying AdministratorAccess to cg-bilbo-vulnerable_lambda_cgid13u1qpdipe |
| 1680023245164 | "result: 200 |
| 1680023245183 | "END RequestId: 4439301b-290c-4ae5-811b-228bb60418c2 |
| 1680023245183 | "REPORT RequestId: 4439301b-290c-4ae5-811b-228bb60418c2	Duration: 294.87 ms	Billed Duration: 295 ms	Memory Size: 128 MB	Max Memory Used: 73 MB	Init Duration: 507.83 ms	 |

According to these Lambda function logs, the `AdministratorAccess` managed 
policy was attached to the `cg-bilbo` IAM user in question. We can confirm this 
by searching for this API call ([`AttachUserPolicy`](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachUserPolicy.html)) 
in CloudTrail.

```sql
select eventtime, eventname, sourceipaddress, useridentity.arn, requestparameters, responseelements
from cloudtrail_logs_pp
where eventname = 'AttachUserPolicy'
and timestamp = '2023/03/28'
```

| eventtime	| eventname	| sourceipaddress	| arn	| requestparameters	| responseelements |
|-----------|-----------|-------------------|-------|-------------------|------------------|
| 2023-03-28T17:07:25Z |	AttachUserPolicy	| 44.200.244.86 |	arn:aws:sts::REDACTED:assumed-role/vulnerable_lambda_cgid13u1qpdipe-policy_applier_lambda1/vulnerable_lambda_cgid13u1qpdipe-policy_applier_lambda1 |	{"userName":"cg-bilbo-vulnerable_lambda_cgid13u1qpdipe","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"} |	

Two interesting things to note here:  
1. The source IP address differs from the previous requests because this API 
call originated from a Lambda function, which runs within internal AWS 
infrastructure
```bash
$ dig +short -x 44.200.244.86
ec2-44-200-244-86.compute-1.amazonaws.com.
```
2. The identity making this API call is a new IAM role that is attached to the 
Lambda function as its execution role 
(`vulnerable_lambda_cgid13u1qpdipe-policy_applier_lambda1`). 

At this point, we've confirmed that the attacker was successfully able to attach
the `AdministratorAccess` managed policy to the compromised IAM user. Given this
access, the attacker was likely able to cause a lot more damage, so let's query
for CloudTrail logs involving the compromised IAM user after the `eventtime` 
associated with the `AttachUserPolicy` event. 

```sql
select eventtime, eventname, sourceipaddress, useridentity.arn, requestparameters, responseelements
from cloudtrail_logs_pp
where useridentity.principalid = 'AIDAREDACTED'
and sourceipaddress = '1.2.3.4'
and from_iso8601_timestamp(eventtime) >  from_iso8601_timestamp('2023-03-28T17:07:25Z')
```

| eventtime |	eventname |	sourceipaddress |	arn |	requestparameters |	responseelements |
|-----------|-------------|-----------------|-------|---------------------|------------------|
| 2023-03-28T17:18:38Z |	ListSecrets |	1.2.3.4 |	arn:aws:iam::REDACTED:user/cg-bilbo-vulnerable_lambda_cgid13u1qpdipe | | |
| 2023-03-28T17:18:59Z |	GetSecretValue |	1.2.3.4 |	arn:aws:iam::REDACTED:user/cg-bilbo-vulnerable_lambda_cgid13u1qpdipe | {"secretId":"vulnerable_lambda_cgid13u1qpdipe-final_flag"} | |

> **NOTE:** If, for some reason, Lambda function logs were not available via 
> CloudWatch or the logs were insufficient, we could proactively hunt for events
> in CloudTrail where the user identity is the Lambda execution role:  
>
>   ```sql
>   select eventtime, useridentity, eventsource, eventname, awsregion, requestparameters, responseelements
>   from cloudtrail_logs_pp
>   where timestamp >= '2023/03/28'
>   and useridentity.arn = 'arn:aws:sts::REDACTED:assumed-role/vulnerable_lambda_cgid13u1qpdipe-policy_applier_lambda1/vulnerable_lambda_cgid13u1qpdipe-policy_applier_lambda1'
>   order by eventtime desc
>   ```
{: .prompt-info }

And we've come full circle. At this point in time, we have confidently 
established a detailed timeline of events.

## Evicting the Attacker

We have to move quickly. The attacker has administrative access to the affected
AWS account, and they've already extracted one of the company's secrets from 
Secrets Manager. 

> In almost every situation, [IAM users should not be used](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html). 
> However, it is worth the effort to identify the owner of the user and confirm 
> whether or not it is being used in production. If it is, this portion of the 
> response playbook will change a bit, as you'll need to carefully create and 
> distribute a new access key for the IAM user before deactivating the 
> compromised key, so as not to cause any unnecessary downtime.
{: .prompt-danger }

### Quarantine the IAM User

In order to prevent the attacker from causing any further damage by using this 
IAM user, we must delete all existing access keys (disabling is not an option 
because disabled access keys [can be re-enabled](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAccessKey.html))
and detaching all IAM policies (both managed and user-defined/inline). 
Additionally, we must comb through the CloudTrail logs in search for any 
attempts to persist or [escalate privileges](https://bishopfox.com/blog/privilege-escalation-in-aws) 
by creating new IAM resources, modifying existing ones, use of alternate methods 
of authentication, etc. We've already conducted this search, but here are some 
common API calls to look for:  
* 

## How can we detect this?

Part three of this series will cover how we can deploy detections designed to 
proactively identify this malicious activity.

Happy (hacking\|hunting)!
