#!/usr/bin/env python

"""gitlamb

Usage:
  gitlamb.py install master [--assumable=<arn>...]
  gitlamb.py install client [<master_account_id>]
  gitlamb.py deploy <app.yaml>
  gitlamb.py simulate <app.yaml> <payload> [--account=<account_id>] [--region=<region>]
  gitlamb.py execute <app.yaml> <payload>

Options:
  -h --help                   Show this screen
  --version                   Show version

"""

import yaml
import json
import StringIO
import zipfile
import os
import boto3
import logging
import hashlib
import base64
import sys
import time

# Fix for a virtualenv problem where it doesn't add the cwd to the python search path
sys.path.insert(0, "")

REGION = "us-east-1"
IAM_DEFAULT_POLICY = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "ec2:CreateNetworkInterface",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DeleteNetworkInterface"
      ],
      "Resource": "*"
    }
  ]
}"""
IAM_DEFAULT_ASSUME_ROLE_POLICY_DOCUMENT = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    },
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::{{CURRENT_ACCOUNT}}:role/gitlamb"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}"""

logging.basicConfig(level=logging.INFO, format="%(message)s")
logging.getLogger('boto').setLevel(logging.CRITICAL)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('requests').setLevel(logging.CRITICAL)


def get_tag(aws_object, tag_name):
	for tag in aws_object['Tags']:
		if tag['Key'] == tag_name:
			return tag['Value']
	return None


class Lambda():

	def __init__(self, app_yaml, session):
		self.app_yaml = app_yaml
		self.log_group_name = "/aws/lambda/{}".format(self.app_yaml['FunctionName'])
		self.session = session

	def simulate(self, payload, account=None, region=None):
		account = self.app_yaml['Accounts'][0]
		region = self.app_yaml['Regions'][0]
		logging.warn("[!] Executing Lambda locally in {}/{}".format(account, region))
		package, name = self.app_yaml['Handler'].split(".", 1)
		logging.warn("[ ] Provisioning Lambda role STS credentials to function environment")

		# STS to the account "gitlamb" role
		sts_client = self.session.client("sts", region_name=region)
		sts_role = sts_client.assume_role(RoleArn="arn:aws:iam::{}:role/gitlamb".format(account), RoleSessionName="GitLamb")
		assumed_session = boto3.Session(region_name=region, aws_access_key_id=sts_role['Credentials']['AccessKeyId'], aws_secret_access_key=sts_role['Credentials']['SecretAccessKey'], aws_session_token=sts_role['Credentials']['SessionToken'])
		# STS to the lambda's role
		sts_client = assumed_session.client("sts", region_name=region)
		sts_role = sts_client.assume_role(RoleArn="arn:aws:iam::{}:role/{}".format(account, self.app_yaml['Role']), RoleSessionName="GitLamb")

		os.environ["AWS_SECRET_ACCESS_KEY"] = sts_role['Credentials']['SecretAccessKey']
		os.environ["AWS_SESSION_TOKEN"] = sts_role['Credentials']['SessionToken']
		os.environ["AWS_ACCESS_KEY_ID"] = sts_role['Credentials']['AccessKeyId']
		imported = getattr(__import__(package, fromlist=[name]), name)
		logging.warn("[ ] Executing:\n----------\n")
		start_time = time.time()
		imported(payload)
		end_time = time.time()
		logging.warn("\n----------\n[ ] Execution took {0:.10f} seconds".format(float(end_time - start_time)))

	def execute(self, payload, account=None, region=None):
		# account = self.app_yaml['Accounts'][0]
		# region = self.app_yaml['Regions'][0]
		for account in self.app_yaml['Accounts']:
			for region in self.app_yaml['Regions']:
				logging.warn("[!] Executing Lambda remotely in account '#{}' and region '{}'".format(account, region))

				sts_client = self.session.client("sts", region_name="us-west-2")
				sts_role = sts_client.assume_role(RoleArn="arn:aws:iam::{}:role/gitlamb".format(account), RoleSessionName="GitLamb")
				assumed_session = boto3.Session(region_name=region, aws_access_key_id=sts_role['Credentials']['AccessKeyId'], aws_secret_access_key=sts_role['Credentials']['SecretAccessKey'], aws_session_token=sts_role['Credentials']['SessionToken'])

				lambda_client = assumed_session.client("lambda", region_name=region)
				logging.warn("[ ] Executing:\n----------\n")
				start_time = time.time()
				response = lambda_client.invoke(FunctionName=self.app_yaml['FunctionName'], InvocationType="RequestResponse", LogType="Tail", Payload=payload)
				end_time = time.time()
				logging.info("{}\n\n{}".format(response['ResponseMetadata'], base64.b64decode(response['LogResult'])))
				logging.warn("\n----------\n[ ] Execution took {0:.10f} seconds".format(float(end_time - start_time)))

	def upsert(self):
		sts_client = self.session.client("sts", region_name=REGION)
		zip_bytes = self.build_zip()
		for account in self.app_yaml['Accounts']:
			account = str(account)
			logging.warn("[ ] Operating in account '{}'".format(account))
			# STS to the relevant gitlamb role in target account to upsert
			sts_role = sts_client.assume_role(RoleArn="arn:aws:iam::{}:role/gitlamb".format(account), RoleSessionName="GitLamb")
			assumed_session = boto3.Session(region_name=REGION, aws_access_key_id=sts_role['Credentials']['AccessKeyId'], aws_secret_access_key=sts_role['Credentials']['SecretAccessKey'], aws_session_token=sts_role['Credentials']['SessionToken'])
			iam_resource = assumed_session.resource("iam", region_name="us-east-1")
			iam_client = assumed_session.client("iam", region_name="us-east-1")
			policy_document = None
			trust_policy = None

			if self.app_yaml.get('RoleDefinition'):
				yaml_role = self.app_yaml['RoleDefinition']
				yaml_role = yaml_role.replace("{{CURRENT_ACCOUNT}}", account)
				yaml_role = json.loads(yaml_role)
				if "PolicyDocument" in yaml_role:
					policy_document = yaml_role['PolicyDocument']
				if "TrustPolicy" in yaml_role:
					trust_policy = yaml_role['TrustPolicy']

			if not policy_document:
				policy_document = IAM_DEFAULT_POLICY
				policy_document = policy_document.replace("{{CURRENT_ACCOUNT}}", account)
				policy_document = json.loads(policy_document)
			if not trust_policy:
				trust_policy = IAM_DEFAULT_ASSUME_ROLE_POLICY_DOCUMENT
				trust_policy = trust_policy.replace("{{CURRENT_ACCOUNT}}", account)
				trust_policy = json.loads(trust_policy)

			try:
				role = iam_client.get_role(RoleName=self.app_yaml['Role'])
			except Exception, e:
				if "NoSuchEntity" not in e.message:
					raise Exception(e)
				if self.app_yaml.get('RoleDefinition'):
					logging.warn("[ ] IAM Role '{}' does not exist; creating with YAML-provided policies ...".format(self.app_yaml['Role']))
				else:
					logging.warn("[ ] IAM Role '{}' does not exist; creating with default policies ...".format(self.app_yaml['Role']))
				role = iam_resource.create_role(RoleName=self.app_yaml['Role'], AssumeRolePolicyDocument=json.dumps(trust_policy))
				role_policy = role.Policy(self.app_yaml['Role'])
				role_policy.put(PolicyDocument=json.dumps(policy_document))
				logging.info("[ ] Pausing for 5 seconds to allow for IAM creation")
				time.sleep(5)
			else:
				if json.dumps(trust_policy, sort_keys=True) != json.dumps(role['Role']['AssumeRolePolicyDocument'], sort_keys=True):
					print "[+] Updating IAM Role role trust policy ..."
					iam_client.update_assume_role_policy(RoleName=self.app_yaml['Role'], PolicyDocument=json.dumps(trust_policy, sort_keys=True))
				try:
					policy = iam_client.get_role_policy(RoleName=self.app_yaml['Role'], PolicyName=self.app_yaml['Role'])
				except:
						print "[+] Creating IAM Role inline policy document ..."
						iam_client.put_role_policy(RoleName=self.app_yaml['Role'], PolicyName=self.app_yaml['Role'], PolicyDocument=json.dumps(policy_document, sort_keys=True))
				else:
					if json.dumps(policy_document, sort_keys=True) != json.dumps(policy['PolicyDocument'], sort_keys=True):
						print "[+] Updating IAM Role inline policy document ..."
						iam_client.put_role_policy(RoleName=self.app_yaml['Role'], PolicyName=self.app_yaml['Role'], PolicyDocument=json.dumps(policy_document, sort_keys=True))

			for region in self.app_yaml['Regions']:
				logging.warn("[ ] Operating in region '{}'".format(region))
				assumed_session = boto3.Session(region_name=region, aws_access_key_id=sts_role['Credentials']['AccessKeyId'], aws_secret_access_key=sts_role['Credentials']['SecretAccessKey'], aws_session_token=sts_role['Credentials']['SessionToken'])
				# Some items will be different according to environment
				local_yaml = dict(self.app_yaml)
				local_yaml['Role'] = "arn:aws:iam::{}:role/{}".format(account, self.app_yaml['Role'])
				vpc_config = None
				target_vpc = None
				if local_yaml.get('VpcConfig'):
					# Todo: Need to support getting VPCs/SGs based on name
					vpc_config = {"SubnetIds": [], "SecurityGroupIds": []}
					# for vpc in json_data['Vpcs']:
					# 	if get_tag(vpc, "Name") == local_yaml['VpcConfig']['VpcName']:
					# 		target_vpc = vpc
					# for subnet in json_data['Subnets']:
					# 	if subnet['VpcId'] == target_vpc['VpcId'] and local_yaml['VpcConfig']['SubnetNameMatch'] in get_tag(subnet, "Name"):
					# 		vpc_config['SubnetIds'].append(subnet['SubnetId'])
					# for securitygroup in json_data['SecurityGroups']:
					# 	if securitygroup['VpcId'] == target_vpc['VpcId'] and securitygroup['GroupName'] in local_yaml['VpcConfig']['SecurityGroups']:
					# 		vpc_config['SecurityGroupIds'].append(securitygroup['GroupId'])
				else:
					vpc_config = {'SubnetIds': [], 'SecurityGroupIds': []}
				lambda_client = assumed_session.client("lambda", region_name=region)
				try:
					lambda_client.get_function(FunctionName=self.app_yaml['FunctionName'])
				except Exception, e:
					logging.warn("[!] Lambda function '{}' does not exist; creating with specified configuration ...".format(self.app_yaml['FunctionName']))
					if "ResourceNotFoundException" not in e.message:
						raise Exception(e)
					logging.warn("[+] Creating function '{}'".format(self.app_yaml['FunctionName']))
					config = {
						"FunctionName": local_yaml['FunctionName'],
						"Runtime": local_yaml['Runtime'],
						"Role": local_yaml['Role'],
						"Handler": local_yaml['Handler'],
						"Code": {"ZipFile": zip_bytes},
						"Description": local_yaml['Description'],
						"Timeout": local_yaml['Timeout'],
						"MemorySize": local_yaml['MemorySize'],
					}
					if vpc_config:
						config["VpcConfig"] = vpc_config
					lambda_client.create_function(**config)
				else:
					config = lambda_client.get_function_configuration(FunctionName=self.app_yaml['FunctionName'])
					if not config.get("VpcConfig"):
						config['VpcConfig'] = {'SubnetIds': [], 'SecurityGroupIds': []}
					matching_keys = ["FunctionName", "Role", "Handler", "Description", "Timeout", "MemorySize"]
					needs_update = False
					# Check if core config is different
					for key in matching_keys:
						if config[key] != local_yaml[key]:
							logging.warn("'{}' != '{}'".format(str(config[key]), local_yaml[key]))
							needs_update = True
					# Check if VPC config is different
					if vpc_config and (set(vpc_config['SubnetIds']) != set(config['VpcConfig']['SubnetIds']) or set(vpc_config['SecurityGroupIds']) != set(config['VpcConfig']['SecurityGroupIds'])):
						needs_update = True
					# Update if needed
					if needs_update:
						logging.warn("[~] Updating Lambda configuration ")
						updated_config = {}
						for key in matching_keys:
							updated_config[key] = local_yaml[key]
						if vpc_config:
							updated_config["VpcConfig"] = vpc_config
						print updated_config
						lambda_client.update_function_configuration(**updated_config)
					else:
						logging.info("[ ] Configuration is up to date; no action required")
					if base64.b64encode(hashlib.sha256(zip_bytes).digest()) != config['CodeSha256']:
						logging.warn("[~] Updating Lambda code")
						lambda_client.update_function_code(**{
							"FunctionName": local_yaml['FunctionName'],
							"ZipFile": zip_bytes
						})
					else:
						logging.info("[ ] Code is up to date; no action required")

	def build_zip(self):

		def zipdir(path, dest_path, zip_handle):
			for root, dirs, files in os.walk(path):
				for file in files:
					zip_handle.write(os.path.join(root, file), os.path.join(root.replace(path, dest_path), file))

		logging.info("[ ] Building ZIP file")
		zio = StringIO.StringIO()
		with zipfile.ZipFile(zio, mode='w') as zf:
			for path in self.app_yaml['Package']:
				dest_path = path
				if " > " in path:
					path, dest_path = path.split(" > ", 2)
				if os.path.isdir(path):
					logging.info("    [+] Adding path {} as {}".format(path, dest_path))
					zipdir(path, dest_path, zf)
				else:
					logging.info("    [+] Adding {} as {}".format(path, dest_path))
					zf.write(path, dest_path)
		# with open("./output.zip", "wb") as output_zip:
		# 	output_zip.write(zio.getvalue())
		value = zio.getvalue()
		logging.info("    [i] Done ~ {:,} bytes".format(len(value)))
		zio.close()
		return value

	def logs_purge(self):
		logging.warn("Deleting log streams for '{}'".format(self.log_group_name))
		for account in self.app_yaml['Accounts']:
			# STS to the relevant RolliePollie role in target account for log management
			#sts_role = sts_client.assume_role(RoleArn="arn:aws:iam::{}:role/RolliePollie".format(account), RoleSessionName="GitLamb")
			for region in self.app_yaml['Regions']:
				#assumed_session = boto3.Session(region_name=region, aws_access_key_id=sts_role['Credentials']['AccessKeyId'], aws_secret_access_key=sts_role['Credentials']['SecretAccessKey'], aws_session_token=sts_role['Credentials']['SessionToken'])
				logs_client = Session.client("logs", region_name=region)
				# TODO: Would be nice to pull current retention setting and recreate
				logging.warn("\t[-] Deleting log group in {}".format(region))
				logs_client.delete_log_group(logGroupName=self.log_group_name)
				logging.warn("\t[+] Creating log group in {}".format(region))
				logs_client.create_log_group(logGroupName=self.log_group_name)
				logs_client.put_retention_policy(logGroupName=self.log_group_name, retentionInDays=1)


if __name__ == '__main__':
	from docopt import docopt
	import sys

	arguments = docopt(__doc__, version='gitlamb 1.0')

	logging.debug("Using IAM credentials from ENV")
	Session = boto3.Session()

	# Find current account id for reference
	account_id = Session.client("sts").get_caller_identity()['Account']
	logging.warn("[ ] Operating from account '{}'".format(account_id))

	if arguments['install']:
		iam_resource = Session.resource("iam", region_name=REGION)
		iam_client = Session.client("iam", region_name=REGION)

		master_role = False
		client_role = False
		for role in iam_resource.roles.all():
			if role.name == "gitlamb_master":
				master_role = role
			if role.name == "gitlamb":
				client_role = role

		if arguments['master']:
			if len(arguments['--assumable']) == 1:
				arguments['--assumable'] = arguments['--assumable'][0]
			if len(arguments['--assumable']) == 0:
				arguments['--assumable'] = Session.client("sts").get_caller_identity()['Arn']
			master_assume_role_policy_document = {u'Version': u'2012-10-17', u'Statement': [{u'Action': u'sts:AssumeRole', u'Principal': {u'AWS': arguments['--assumable']}, u'Effect': u'Allow', u'Sid': u''}]}
			master_policy_document = {u'Version': u'2012-10-17', u'Statement': [{u'Action': [u'sts:AssumeRole'], u'Resource': [u'arn:aws:iam::*:role/gitlamb'], u'Effect': u'Allow', u'Sid': u'Stmt1475434420000'}]}
			if not master_role:
				print "[+] Createing gitlamb_master IAM role"
				iam_client.create_role(RoleName='gitlamb_master', AssumeRolePolicyDocument=json.dumps(master_assume_role_policy_document))
				master_role = iam_resource.Role("gitlamb_master")
			if json.dumps(master_role.assume_role_policy_document, sort_keys=True) != json.dumps(master_assume_role_policy_document, sort_keys=True):
				print "[~] Modifying master assume role policy document"
				assume_role_policy = iam_resource.AssumeRolePolicy('gitlamb')
				assume_role_policy.update(PolicyDocument=json.dumps(master_assume_role_policy_document))
			master_policy = None
			for policy in master_role.policies.all():
				if policy.name == "gitlamb_master":
					master_policy = policy
			if not master_policy:
				master_policy = master_role.Policy('gitlamb_master')
				master_policy.put(PolicyDocument=json.dumps(master_policy_document))
			if json.dumps(master_policy.policy_document, sort_keys=True) != json.dumps(master_policy_document, sort_keys=True):
				print "[~] Modifying master role policy document"
				master_policy.put(PolicyDocument=json.dumps(master_policy_document))

		if arguments['client']:
			if not arguments['<master_account_id>']:
				arguments['<master_account_id>'] = account_id
			client_assume_role_policy_document = {u'Version': u'2012-10-17', u'Statement': [{u'Action': u'sts:AssumeRole', u'Principal': {u'AWS': u'arn:aws:iam::{}:role/gitlamb_master'.format(arguments['<master_account_id>'])}, u'Effect': u'Allow', u'Sid': u''}]}
			client_policy_document = {u'Version': u'2012-10-17', u'Statement': [{u'Action': [u'lambda:*'], u'Resource': [u'*'], u'Effect': u'Allow', u'Sid': u'Stmt1475424995000'}, {u'Action': [u'iam:GetRole', u'iam:GetRolePolicy', u'iam:PutRolePolicy', u'iam:CreateRole', u'iam:ListRoles', u"iam:UpdateAssumeRolePolicy", u"iam:PassRole"], u'Resource': [u'*'], u'Effect': u'Allow', u'Sid': u'Stmt1475425951000'}]}
			if not client_role:
				print "[+] Creating gitlamb IAM role"
				iam_client.create_role(RoleName='gitlamb', AssumeRolePolicyDocument=json.dumps(client_assume_role_policy_document))
				client_role = iam_resource.Role("gitlamb")
			if json.dumps(client_role.assume_role_policy_document, sort_keys=True) != json.dumps(client_assume_role_policy_document, sort_keys=True):
				print "[~] Modifying client assume role policy document"
				assume_role_policy = iam_resource.AssumeRolePolicy('gitlamb')
				assume_role_policy.update(PolicyDocument=json.dumps(client_assume_role_policy_document))
			client_policy = None
			for policy in client_role.policies.all():
				if policy.name == "gitlamb":
					client_policy = policy
			if not client_policy:
				client_policy = client_role.Policy('gitlamb')
				client_policy.put(PolicyDocument=json.dumps(client_policy_document))
			if json.dumps(client_policy.policy_document, sort_keys=True) != json.dumps(client_policy_document, sort_keys=True):
				print "[~] Modifying client role policy document"
				client_policy.put(PolicyDocument=json.dumps(client_policy_document))
	else:
		sts_client = Session.client("sts", region_name="us-east-1")
		sts_role = sts_client.assume_role(RoleArn="arn:aws:iam::{}:role/gitlamb_master".format(account_id), RoleSessionName="GitLamb")
		master_session = boto3.Session(region_name=REGION, aws_access_key_id=sts_role['Credentials']['AccessKeyId'], aws_secret_access_key=sts_role['Credentials']['SecretAccessKey'], aws_session_token=sts_role['Credentials']['SessionToken'])

	if arguments['deploy']:
		with open(arguments['<app.yaml>'], "r") as f:
			app_yaml = yaml.safe_load(f)
		lamb = Lambda(app_yaml, master_session)
		lamb.upsert()

	if arguments['simulate']:
		with open(arguments['<app.yaml>'], "r") as f:
			app_yaml = yaml.safe_load(f)
		lamb = Lambda(app_yaml, master_session)
		lamb.simulate(payload=json.loads(arguments['<payload>']))

	if arguments['execute']:
		with open(arguments['<app.yaml>'], "r") as f:
			app_yaml = yaml.safe_load(f)
		lamb = Lambda(app_yaml, master_session)
		lamb.execute(payload=arguments['<payload>'])
