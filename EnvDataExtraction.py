#!/usr/bin/env python3

import aws_sso_lib
import boto3
import configparser
import os
import sys
from botocore.config import Config
import json


def login(start_url: str, sso_region: str) -> dict:
    """Login to AWS with SSO account

    Args:
        start_url (str): SSO start URL.
        sso_region (str): SSO region.

    Returns:
        dict: Returns the token dict as returned by sso-oidc:CreateToken, which contains the actual authorization token, as well as the expiration
    """
    return aws_sso_lib.login(
        start_url=start_url,
        sso_region=sso_region,
    )


def get_role_credentials(accessToken: dict, account_id: str, role_name: str, region: str = "us-east-1") -> dict:
    """Create sso client for the given account and return temporary aws credentials

    Args:
        accessToken (dict): The token issued by the CreateToken API call
        account_id (str): aws account number
        role_name (str): aws role account name
        region (str, optional): Region for API calls. Defaults to "us-east-1".

    Returns:
        dict: Dict with temporary aws credentials
    """
    client = boto3.client('sso', region_name=region)
    response = client.get_role_credentials(
        roleName=role_name,
        accountId=account_id,
        accessToken=accessToken
    )

    return response['roleCredentials']


def write_creds(roleCredentials: dict, account_name: str, aws_credentials: str = '~/.aws/credentials', aws_config: str = '~/.aws/config'):
    """Save aws credentials to corresponding config files.
       Add default profile if it not already present in the config file.

    Args:
        roleCredentials (dict): roleCredentials
        aws_credentials (str, optional): Configuration file. Defaults to '~/.aws/credentials'.
        aws_config (str, optional): Credential file. Defaults to '~/.aws/config'.
    """
    config = configparser.ConfigParser()
    config.read(os.path.expanduser(aws_credentials))
    credentials = {
        "aws_access_key_id": roleCredentials['accessKeyId'],
        "aws_secret_access_key": roleCredentials['secretAccessKey'],
        "aws_session_token": roleCredentials['sessionToken'],
    }
    if account_name in config.sections():
        config[account_name] = credentials
        with open(os.path.expanduser(aws_credentials), 'w+') as credentials_file:
            config.write(credentials_file)
    else:
        config.add_section(account_name)
        config.read(os.path.expanduser(aws_credentials))
        config[account_name] = credentials
        with open(os.path.expanduser(aws_credentials), 'w+') as credentials_file:
            config.write(credentials_file)

    config = configparser.ConfigParser()

    try:
        config.read_file(open(os.path.expanduser(aws_config)))
    except FileNotFoundError:
        open(os.path.expanduser(aws_config), "x")
    if not config.has_section(f"""profile {account_name}"""):
        config.add_section(f"""profile {account_name}""")
        with open(os.path.expanduser(aws_config), 'w') as config_file:
            config.write(config_file)


def set_default_profile(roleCredentials: dict, aws_credentials: str = '~/.aws/credentials', aws_config: str = '~/.aws/config'):
    account_name = "default"
    config = configparser.ConfigParser()
    config.read(os.path.expanduser(aws_credentials))
    credentials = {
        "aws_access_key_id": roleCredentials['accessKeyId'],
        "aws_secret_access_key": roleCredentials['secretAccessKey'],
        "aws_session_token": roleCredentials['sessionToken'],
    }

    if account_name in config.sections():
        config[account_name] = credentials
        with open(os.path.expanduser(aws_credentials), 'w+') as credentials_file:
            config.write(credentials_file)
    else:
        config.add_section(account_name)
        config.read(os.path.expanduser(aws_credentials))
        config[account_name] = credentials
        with open(os.path.expanduser(aws_credentials), 'w+') as credentials_file:
            config.write(credentials_file)

    config = configparser.ConfigParser()

    try:
        config.read_file(open(os.path.expanduser(aws_config)))
    except FileNotFoundError:
        open(os.path.expanduser(aws_config), "x")
    if not config.has_section(f"""profile {account_name}"""):
        config.add_section(f"""profile {account_name}""")
        with open(os.path.expanduser(aws_config), 'w') as config_file:
            config.write(config_file)


def choose_account_role(accounts: list, desired_account_name: str) -> dict:
    """Ask to choose an account with interactive cli

    Args:
        accounts (list): List of account in tuples in format [(account_id, account_name, role_name)].

    Returns:
        dict: { 'account_id': account_id, 'role_name': role_name }
    """

    for account in accounts:
        if account[1] == desired_account_name and account[2] == 'AWSAdministratorAccess':
            return {'account_name': account[1],
                    'account_id': account[0],
                    'role_name': account[2]}
    print(f'{desired_account_name} was not found in the account list')


def access_codeAF(account_name):
    os.system(
        f"""aws codeartifact login --tool pip --repository Pagaya-Artifacts-prod --domain pagaya-artifacts --domain-owner 704102000649 --region us-east-1 --profile {account_name} """)


def access_codeAF_boto3(account_name, role_name):
    session = boto3.Session(profile_name=account_name)
    client = session.client('codeartifact', region_name="us-east-1")
    try:
        response = client.get_authorization_token(
            domain='pagaya-artifacts',
            domainOwner='704102000649'
        )
    except:
        print(f"""The role {role_name} in account {account_name} doesnt have access to code artifact!
                  Please contact DevOps for assistance!""")
        sys.exit(1)

    config_path = "~/.config"
    pip_dir_path = "~/.config/pip/"
    pip_path = "~/.config/pip/pip.conf"
    auth_token = response["authorizationToken"]
    index = {"index-url": f"""https://aws:{auth_token}@pagaya-artifacts-704102000649.d.codeartifact.us-east-1.amazonaws.com/pypi/Pagaya-Artifacts-prod/simple/"""}

    os.makedirs(os.path.dirname(os.path.expanduser(config_path)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.expanduser(pip_dir_path)), exist_ok=True)
    config = configparser.ConfigParser()
    if os.path.isfile(os.path.expanduser(pip_path)) is False:
        with open(os.path.expanduser(pip_path), "w+") as f:
            f.close()
    config.read(os.path.expanduser(pip_path))

    if "global" not in config.sections():
        config.add_section("global")

    with open(os.path.expanduser(pip_path), 'w+') as config_file:
        config["global"] = index
        config.write(config_file)


def login_to_account(desired_account_name: str):
    start_url = "https://d-906766c0db.awsapps.com/start/"
    sso_region = "us-east-1"
    accounts = [account for account in aws_sso_lib.list_available_roles(start_url=start_url, sso_region=sso_region, login=True)]
    account_role = choose_account_role(accounts, desired_account_name)
    account_id, role_name, account_name = account_role["account_id"], account_role["role_name"], account_role["account_name"]
    print("account_name: ", account_name)
    print("account_id: ", account_id)
    print("role_name: ", role_name)
    session = login(start_url=start_url, sso_region=sso_region)
    role_credentials = get_role_credentials(accessToken=session['accessToken'], account_id=account_id, role_name=role_name)
    set_default_profile(role_credentials)
    write_creds(role_credentials, account_name)


def main():
    login_to_account('Eng-Dev')
    my_config = Config(
        region_name='us-east-1',
    )

    client = boto3.client('apigateway', config=my_config)
    domain_names_list = json.dumps(client.get_domain_names(), indent=2, default=str)
    print('domain name list:\n')
    # for domain_name in domain_names_list:
    #     print(domain_name)
    print(f'domain names list:\n{domain_names_list}')

    #     print(for domain_name in domain_names_list F'domain names list:\n{domain_names_list}')
    # domain_names_list = os.popen("aws apigateway get-domain-names --region us-east-1")
    # print(domain_names_list.read())


if __name__ == "__main__":
    main()
