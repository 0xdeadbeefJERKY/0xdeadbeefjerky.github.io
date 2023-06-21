---
title:  "CloudGoat Vulnerable Lambda Scenario - Part 2 (Response)"
description: > 
    As an incident responder, walk through how we can investigate and resolve an
    ongoing attack targeting CloudGoat's vulnerable Lambda scenario.
date: 2023-06-21 00:15:40-04:00
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
function with an inherent SQL injection vulnerability using a compromised AWS 
access key, escalate our privileges and subsequently access company secrets. In 
this post (part two), we'll assume the role of a responder (e.g., SOC analyst, 
IR team member) and conduct an investigation with the goal of evicting the 
attacker from the affected AWS environment. The structure of this post will 
loosely follow [NIST's incident handling guide](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-61r2.pdf)
as well as the [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html):  
* ~~Preparation~~ (skip this, as we're dealing with an "active" incident)
* Detection and Analysis
* Containment, Eradication and Recovery
* ~~Post-Incident Activity~~ (we'll cover this in future posts)

## Detection: The Initial Alert

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

## Analysis: Building Context and Timeline

A responder's ability to quickly and effectively investigate an incident is 
almost entirely dependent on the context that's made available to them. In this 
example, the context is quite limited (intentionally), so we're left to build 
it out on our own.

### Analyze Cloudtrail Logs Using Athena

We know that a secret within AWS Secrets Manager was accessed from a suspicious 
IP. Let's pivot on the secret ID in question by pulling the relevant CloudTrail 
logs - events with an event name of `GetSecretValue` further filtered on both 
the secret ID (`CloudTrailEvent:requestParameters:secretId`) and the source IP
address. There are many options to sift through and analyze CloudTrail data, 
such as piping output from the AWS CLI to a utility (e.g., `jq`), using the 
Python SDK and storing the output as a Pandas DataFrame (ideally, [using a Jupyter notebook](https://catalog.workshops.aws/incident-response-jupyter/en-US)), 
etc. Because we're dedicated to the theme of using native AWS services and 
tooling when possible, we'll [query CloudTrail logs using Athena](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html) 
for this purpose.

Execute [this bash script](https://gist.github.com/0xdeadbeefJERKY/25eb17714657ce3847a299a84648a26d)
to setup the necessary Athena components for CloudTrail log analysis. For 
example:  

```bash
./aws-setup-cloudtrail-investigation.sh \ 
   -c cloudtrail-logs-123/AWSLogs/REDACTED/CloudTrail/us-east-1 \ # full S3 bucket path to CloudTrail logs
   -w secret-exposure-workgroup \ # name of Athena workgroup
   -d "workgroup for investigating incident XYZ" \ # Athena workgroup description
   -a us-east-1 \ # Athena workgroup region
   -r athena-results-456 \ # bucket to store Athena query results
   -n cloudtrail_logs_us_east_1 \ # Athena table name
   -s "2023/03/01" # CloudTrail logs start date
   -e "2023/03/08" # CloudTrail logs end date
```

> **NOTE:** The CloudTrail "Event history" section in the console has a "Create 
> Athena table" option. However, the resulting SQL statement doesn't account for 
> partitioning, which may unnecessarily increase query time and costs, depending 
> on the size of the trail being imported to Athena.
{: .prompt-info }

Now, we can begin our investigation! Navigate to Athena in the AWS console, open
up a new tab within the query editor:  

![cloudgoat](/assets/img/athena.png){: .center-image}

Choose the newly created workgroup using the dropdown in the top-right:  

![cloudgoat](/assets/img/workgroup.png){: .center-image}

Locate the initial CloudTrail event that likely produced the alert:      

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

It's entirely possible that the attacker has used this compromised access key 
from multiple IP addresses to throw us off. However, in order to detangle the 
attacker activity from legitimate use of the same access key, we would need to
determine when the access key was compromised and perform a retroactive analysis
of the IAM user's activity to identify outliers based on known-good IP 
addresses, user agent string, etc.

Additionally, we should pivot solely on the source IP address to determine if 
the attacker is present elsewhere in the same AWS account. This could be done to
rule out the possibility that the attacker was able to compromise this IAM user
account through some other compromised identity or resource in the account. 

The initial set of API calls leading up to the call to `AssumeRole` is 
interesting, as those calls appear to be potential reconnaissance (series of 
`Get*` and `List*` requests). To confirm this suspicion, let's dig into the 
request parameters. It'd be quite strange for a legitimate user to make a bunch
of API calls to determine what permissions they had, no?

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
cloud account has been compromised. Ironically, security practitioners often 
find themselves needing to perform a bit of discovery as well because they 
typically don't have deep insight into their organization's infrastructure, 
identities, workloads, etc. More specifically, it would be really helpful to 
understand what permissions this IAM user had at the time of compromise (before
the attacker had a chance to make any IAM-specific changes). Unless our 
organization has AWS Config setup, our only other option is to dig through 
CloudTrail logs and manually piece together relevant IAM events. Let's enumerate 
this IAM user's current permissions, then we can sweep CloudTrail events for any 
IAM actions targeting this IAM user. The results won't be 100% accurate, but 
it's at least a reference point.

```bash
# list inline policies attached to user
aws iam list-user-policies --user-name cg-bilbo-vulnerable_lambda_cgid13u1qpdipe
{
    "PolicyNames": [
        "cg-bilbo-vulnerable_lambda_cgid13u1qpdipe-standard-user-assumer"
    ]
}
# get policy document
aws iam get-user-policy --user-name cg-bilbo-vulnerable_lambda_cgid13u1qpdipe --policy-name cg-bilbo-vulnerable_lambda_cgid13u1qpdipe-standard-user-assumer
{
    "UserName": "cg-bilbo-vulnerable_lambda_cgid13u1qpdipe",
    "PolicyName": "cg-bilbo-vulnerable_lambda_cgid13u1qpdipe-standard-user-assumer",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Effect": "Allow",
                "Resource": "arn:aws:iam::REDACTED:role/cg-lambda-invoker*",
                "Sid": ""
            },
            {
                "Action": [
                    "iam:Get*",
                    "iam:List*",
                    "iam:SimulateCustomPolicy",
                    "iam:SimulatePrincipalPolicy"
                ],
                "Effect": "Allow",
                "Resource": "*",
                "Sid": ""
            }
        ]
    }
}
# list managed policies attached to user
aws iam list-attached-user-policies --user-name cg-bilbo-vulnerable_lambda_cgid13u1qpdipe
{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ]
}
# list group memberships
aws iam list-groups-for-user --user-name cg-bilbo-vulnerable_lambda_cgid13u1qpdipe
{
    "Groups": []
}
# list inline policies attached to group
# aws iam list-group-policies --group-name <group_name>
# list managed policies attached to group
# aws iam list-attached-group-policies --group-name <group_name>
```

According to the current state of the affected IAM user, they have full 
administrative access to the entire account, courtesy of the 
`AdministratorAccess` managed policy. Additionally, they're able to assume any 
IAM role prepended with "cg-lambda-invoker." Let's determine which IAM roles the 
user was able to assume, and what subsequent actions they were able to perform 
using that role.

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

![cloudgoat](/assets/img/cw1.png){: .center-image}

3. Select the appropriate log group (e.g., `/aws/lambda/my-function`). In this 
case, `/aws/lambda/vulnerable_lambda_cgid13u1qpdipe-policy_applier_lambda1`.

4. Multiple log streams may exist. Be sure to choose the stream that contains 
logs covering the same time frame as the call to `Invoke` noted in the 
CloudTrail events (in this case, 2023-03-28T17:07:25Z)

![cloudgoat](/assets/img/cw2.png){: .center-image}

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


> **NOTE:** If, for some reason, Lambda function logs were not available via 
> CloudWatch or the logs were insufficient, we could proactively hunt for events
> in CloudTrail where the user identity is the Lambda execution role:  
>
>   ```sql
>   select eventtime, useridentity, eventsource, eventname, awsregion, requestparameters, responseelements
>   from cloudtrail_logs_pp
>   where timestamp >= '2023/03/28'
>   and useridentity.sessioncontext.sessionissuer.username = 'vulnerable_lambda_cgid13u1qpdipe-policy_applier_lambda1'
>   order by eventtime desc
>   ```
{: .prompt-info }

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

And we've come full circle. At this point in time, we have confidently 
established a detailed timeline of events.

## Containment

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
IAM user, we must delete the affected access keys (disabling isn't preferred 
because disabled access keys [can be re-enabled](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAccessKey.html)). 
Note that deleting an access key is an irreversible action, so be sure to 
properly document the access key ID somewhere (e.g., incident report) for record 
keeping.

```bash
# delete the access key 
aws iam delete-access-key --access-key-id AKIAREDACTED
```

If we were able to confidently determine that the compromised IAM user is _not_ 
currently in use by critical applications, infrastructure, etc., we can also 
attach a "deny all" IAM policy to ensure the IAM user is fully quarantined, 
preventing further compromise.

```bash
aws iam put-user-policy --user-name cg-bilbo-vulnerable_lambda_cgid13u1qpdipe \ 
    --policy-name 'DenyAllQuarantine' \ 
    --policy-document '{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}'
```

## Eradication

Now that the user is effectively quarantined, we must comb through the 
CloudTrail logs in search for any attempts to persist or [escalate privileges](https://bishopfox.com/blog/privilege-escalation-in-aws) 
by creating new IAM resources, modifying existing ones, use of alternate methods 
of authentication, etc. We've already conducted this search and confirmed that
the attacker was successful in attaching the managed `AdministratorAccess` 
policy to the compromised IAM user. We'll need to detach this policy to return 
the IAM user to a "known good" state:  

```bash
# detach the managed AdministratorAccess policy
aws iam detach-user-policy --user-name cg-bilbo-vulnerable_lambda_cgid13u1qpdipe \ 
    --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"
```

## Recovery

We're not out of the woods just yet. The Lambda function is still open to 
exploitation and offers up a method for trivial privilege escalation by way of 
the SQL injection vulnerability. To remedy this, we need to work with the owner
of the Lambda function to patch the relevant Python code. In this case, we need
to remove the string concatenation and replace it with a [prepared statement that leverages a parameterized query](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html#defense-option-1-prepared-statements-with-parameterized-queries).
This can be achieved using the `sqlite_utils` library that's already in use by
the Lambda function, specifically by [passing parameters](https://sqlite-utils.datasette.io/en/stable/python-api.html#passing-parameters) 
to the `db.query()` method:  

```diff
<     statement = f"select policy_name from policies where policy_name='{policy}' and public='True'"
<     for row in db.query(statement):
---
>     prepared_statement = "select policy_name from policies where policy_name=? and public='True'"
>     for row in db.query(prepared_statement, [policy]):
```

This change can be made from the AWS console via the Lambda function's "Code" tab 
(don't forget to click "Deploy"). Next, navigate to the "Test" tab and create a 
new event using the following parameters:  

```json
{
  "user_name": "cg-bilbo-vulnerable_lambda_cgid13u1qpdipe",
  "policy_names": ["AdministratorAccess'; --"]
}
```

The test response confirms that our fix is working as expected!  

```bash
Test Event Name
myTestEvent

Response
"AdministratorAccess'; -- is not an approved policy, please only choose from approved policies and don't cheat. :) "

Function Logs
START RequestId: 1eb04d3d-8b02-4b7c-9e7c-4602bad751c7 Version: $LATEST
target policys are : ["AdministratorAccess'; --"]
AdministratorAccess'; -- is not an approved policy, please only choose from approved policies and don't cheat. :) 
```

## How can we detect this?

Part three of this series will cover how we can deploy detections designed to 
proactively identify this malicious activity.

Happy (hacking\|hunting)!
