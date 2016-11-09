# GitLamb
GitLamb is a simple AWS Lambda deployment and management framework. The goal of GitLamb is to make it simple to create/update AWS Lambda functions across multiple AWS accounts and regions and make them a little easier to debug and simulate on your local machine. GitLamb is not a framework for your application to run with, rather it is simply an easy(ier) way to deploy and test arbitrary applications as Lambda function code.

## Setup
Each account you want to manage via GitLamb will need a “gitlamb“ IAM role which is used by GitLamb to do lambda function management. These “gitlamb” roles should be configured with a trust relationship back to a central role called “gitlamb_master”. Your local IAM role or user used to do AWS management should be able assume role (STS) into this “gitlamb_master” account. This creates a hub-and-spoke model where a central management account is trusted by all of client accounts.

The “gitlamb” client IAM roles have the ability to create IAM roles and all Lambda privileges in each of their respective accounts.

The “gitlamb_master” IAM role has the ability to Assume Role into each of the client roles, and be assumed into from your IAM user or role.

