# EC2 deployment with SSM and GitHub OIDC

This deployment keeps the current EC2 + Docker Compose architecture but removes
the GitHub Actions SSH private key. The workflow:

1. Runs the backend tests and web build.
2. Assumes an AWS IAM role using GitHub's short-lived OIDC token.
3. Uploads an immutable release archive to S3.
4. Uses Systems Manager Run Command to deploy the archive on EC2.
5. Runs the guarded production migration.
6. Restarts and verifies the Compose services.

The production environment is stored in the protected GitHub `production`
environment as the `PRODUCTION_ENV_FILE` secret. Each deployment synchronizes
that secret to the encrypted SSM parameter `/gps-tracker/production/env`, then
fetches it onto the EC2 host as `.env` immediately before Docker Compose starts.

## GitHub environment

Create a GitHub environment named `production` and add these secrets:

| Secret | Value |
| --- | --- |
| `AWS_DEPLOY_ROLE_ARN` | ARN of the GitHub OIDC deployment role |
| `RELEASE_BUCKET` | S3 bucket used for release archives |
| `EC2_INSTANCE_ID` | Target EC2 instance ID |
| `EC2_APP_DIR` | `/home/ubuntu/gps-tracker` |
| `PRODUCTION_ENV_FILE` | Complete production `.env` contents |

The workflow is `.github/workflows/deploy-ec2.yml`.

## AWS prerequisites

The EC2 instance must be a Systems Manager managed node. It needs:

- SSM Agent installed and running.
- An instance profile containing `AmazonSSMManagedInstanceCore`.
- AWS CLI installed.
- Outbound HTTPS access to SSM and S3 endpoints.
- Docker Compose available to the `ubuntu` user through `sudo`.

The GitHub deployment role also needs `ssm:PutParameter` for
`/gps-tracker/production/env`. The EC2 instance role needs `ssm:GetParameter`
for that parameter and `kms:Decrypt` for the KMS key used by the SecureString.

Create an S3 bucket in `ap-south-1` with Block Public Access and default
encryption. Restrict its use to the release prefix and add a lifecycle rule to
expire old release archives.

## GitHub OIDC provider

Create the IAM OIDC provider:

```text
Provider URL: https://token.actions.githubusercontent.com
Audience: sts.amazonaws.com
```

The deployment role trust policy should be restricted to this repository and
the production environment. Replace the account ID as appropriate:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GitHubProductionEnvironment",
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:mystikraz/GpsTracker:environment:production"
        }
      }
    }
  ]
}
```

Do not use a trust policy that permits every repository or every branch in the
GitHub organization.

## GitHub deployment-role policy

Attach a policy like this to the deployment role. Replace the account ID and
bucket name. The SSM document and target instance are both restricted.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "UploadRelease",
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::<RELEASE_BUCKET>/releases/*"
    },
    {
      "Sid": "SendDeploymentCommand",
      "Effect": "Allow",
      "Action": "ssm:SendCommand",
      "Resource": [
        "arn:aws:ssm:ap-south-1::document/AWS-RunShellScript",
        "arn:aws:ec2:ap-south-1:<ACCOUNT_ID>:instance/<INSTANCE_ID>"
      ]
    },
    {
      "Sid": "ReadDeploymentResult",
      "Effect": "Allow",
      "Action": "ssm:GetCommandInvocation",
      "Resource": "*"
    },
    {
      "Sid": "WriteProductionEnvironment",
      "Effect": "Allow",
      "Action": "ssm:PutParameter",
      "Resource": "arn:aws:ssm:ap-south-1:<ACCOUNT_ID>:parameter/gps-tracker/production/env"
    }
  ]
}
```

`ssm:GetCommandInvocation` does not provide a useful resource-level
restriction for this workflow, so it is kept as a separate statement.

## EC2 instance-role policy

The EC2 instance role needs SSM management permissions and read access to only
the release prefix:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadReleaseArchives",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::<RELEASE_BUCKET>/releases/*"
    },
    {
      "Sid": "ReadReleaseBucketLocation",
      "Effect": "Allow",
      "Action": "s3:GetBucketLocation",
      "Resource": "arn:aws:s3:::<RELEASE_BUCKET>"
    },
    {
      "Sid": "ReadProductionEnvironment",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "kms:Decrypt"
      ],
      "Resource": [
        "arn:aws:ssm:ap-south-1:<ACCOUNT_ID>:parameter/gps-tracker/production/env",
        "arn:aws:kms:ap-south-1:<ACCOUNT_ID>:key/<KMS_KEY_ID>"
      ]
    }
  ]
}
```

Attach AWS's managed `AmazonSSMManagedInstanceCore` policy to the same EC2
instance role for Systems Manager connectivity.

## First-time verification

Verify the instance is managed:

```powershell
aws ssm describe-instance-information --region ap-south-1
```

Verify the GitHub role before deploying:

```yaml
- name: Verify AWS identity
  run: aws sts get-caller-identity
```

Then run the workflow manually from GitHub Actions. A push to `main` also
triggers deployment.

## Rollback

Each archive is stored under its commit SHA. To roll back, invoke SSM with the
previous archive key, then rebuild and restart the Compose services using the
same migration and verification commands.

Do not delete the active release archive until the replacement deployment has
passed verification.
