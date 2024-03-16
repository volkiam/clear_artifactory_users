#!/usr/bin/env python

import requests, json, base64
import os
import ldap3
import json
import logging
from ldap3 import Connection
from ldap3.utils.log import set_library_log_activation_level

# get LDAP variables from env
LDAP_USER = os.getenv('JFROG_LDAP_USER', 'user')
LDAP_PASSWORD = os.getenv('JFROG_LDAP_PASSWORD', 'password')
LDAP_SERVER = os.getenv('JFROG_IPA_SERVER', 'dc01.company.local')
LDAP_USER_TYPE = os.getenv('JFROG_LDAP_USER_TYPE', 'user') # sysaccount
# set default variables
DC = 'dc=company,dc=local'
IPA_SYSACCOUNT = 'uid={},cn=sysaccounts,dc=company,dc=local'
IPA_USER = 'uid={},cn=users,dc=company,dc=local'

# get Artifactory variables  from env
ARTIFACTORY_USER = os.getenv('ARTIFACTORY_USER', 'user')
ARTIFACTORY_TOKEN = os.getenv('ARTIFACTORY_TOKEN', 'user')

# Set LOG vars 
LOG_DIRECTORY = os.getenv('JFROG_LOG_DIRECTORY', './app/logs')
LOG_TO_FILE = os.getenv('JFROG_LOG_TO_FILE', 'no')
LOG_LEVEL = os.getenv('JFROG_LOG_LEVEL', logging.INFO)

# reset connection variable
conn = None

# Initialize log file
log_format = '%(levelname)s [%(asctime)s] %(message)s'
datefmt = '%d-%b-%y %H:%M:%S'
if LOG_TO_FILE == 'yes':
    logfile = LOG_DIRECTORY + "/jfrogldap.log"
    print("Use logfile %s" % logfile)
    try:
        logging.basicConfig(
            filename=logfile,
            filemode='w',
            format=log_format,
            datefmt=datefmt
        )
    except OSError as logerror:
        logging.basicConfig(format=log_format, datefmt=datefmt)
        logging.error("Cannot open logfile {}, using stdout. error:{}".format(logfile, logerror))
else:
    logging.basicConfig(format=log_format, datefmt=datefmt)

logging.getLogger().setLevel(LOG_LEVEL)
set_library_log_activation_level(LOG_LEVEL)

# LDAP communication setup
def ldap_connect(conn: Connection, ldap_server: str, username: str, password: str, usertype: str = "sysaccount") -> Connection:
    """
    LDAP connection
    Args:
        conn (Connection): Check if connection to LDAP server already exists   
        ldap_server (str): LDAP server
        username (str): LDAP user
        password (str):  LDAP user password
        usertype (str, default value: "sysaccount"): LDAP user type
    Returns:
        Connection: LDAP connection
    """
    if conn:
        return conn
    
    user = IPA_USER.format(username)
    if usertype == "sysaccount":
        user = IPA_SYSACCOUNT.format(username)

    conn = ldap3.Connection(ldap_server, user=user, password=password)
    if not conn.bind():
        log_error("LDAP connection failed", conn.result)
        raise(Exception("LDAP connection failed! %s" % conn.result['message']))
    return conn

# get LDAP user by uid
def ldap_get_user(conn: Connection, ldap_server: str, username: str, password: str, usertype: str = "sysaccount", find_uid: str = ""):
    """
    LDAP Get all users with specified uid
    Args:
        conn (Connection): Connection to LDAP server  
        username (str): LDAP user
        password (str):  LDAP user password
        usertype (str, default value: "sysaccount"): LDAP user type
        find_uid (str): uid for search request
    Returns:
        array of users
    """
    connect = ldap_connect(conn, ldap_server, username, password, usertype)
    connect.search(
        f'cn=users,cn=accounts,{DC}',
        search_filter=f'(uid=' + find_uid + ')',
        size_limit=0,
        attributes=['uid', 'mail', 'nsAccountLock'],
        search_scope=ldap3.SUBTREE,
    )
    print(len(connect.response))
    if len(connect.response) == 0:
        result = None
    else:
        result = connect.response[0]
    return result 


# Create log message
@staticmethod
def log_error(message: str, res: dict) -> None:
    """
    Log error code and message
    Args:
        param res (str): Result from LDAP query
        param message (dict): Additional message to log
    Returns:
        None
    """
    logging.error("%s. Error code: %d, Message: %s" % (message, res['result'], res['message']))

# Artifactory communication

# def get_bearer_token (url: str, user_token: str):
#     headers = {
#         "Authorization": "Bearer " + user_token,
#         'Accept': 'application/json'
#     }
#     data = {
#         "scope": "applied-permissions/user"
#     }
#     response = requests.post(url, headers=headers, data=data)
#     return response.json().get("access_token").encode("ascii","ignore")

# Check if artifactory server is available 
def check_availability (main_url: str):
    """
    Check availability for artifactory server
    Args:
        main_url (str): Artifactory service url
    Returns:
        Query result
    """
    response = requests.get(main_url)
    return response.text

# Get users list
def get_users_list (main_url: str, user_token: str):
    """
    Get artifactory users list
    Args:
        main_url (str): Artifactory service url
        user_token (str): Access user token
    Returns:
        Users list (json)
    """
    headers = {
        "Authorization": "Bearer " + user_token,
        'Accept': 'application/json'
    }
    url = f'{main_url}/access/api/v2/users'
    response = requests.get(url, headers=headers)
    return response.json()

# Get user information
def get_user_details (main_url, token, username):
    """
    Get artifactory user information
    Args:
        main_url (str): Artifactory service url
        token (str): Access user token
        username (str): Artifactory user name for get detailed information
    Returns:
        User info (json)
    """
    headers = {
        "Authorization": "Bearer " + token,
        'Accept': "application/scim+json; charset=UTF-8"
    }
    url = f'{main_url}/access/api/v2/users/{username}'
    response = requests.get(url, headers=headers)
    return response.json()  

# Delete user from artifactory
def delete_user (main_url, token, username):
    """
    Delete artifactory user
    Args:
        main_url (str): Artifactory service url
        token (str): Access user token
        username (str): Artifactory user name for delete from artifactory users
    Returns:
        Delete query result (json)
    """
    headers = {
        "Authorization": "Bearer " + token,
    }
    url = f'{main_url}/access/api/v2/users/{username}'
    response = requests.delete(url, headers=headers)
    return response.json() 


# Main
def main() -> None:
    """
    main
    
    Search for artifactory users with saml auth who are blocked in LDAP and remove them from the list of artifactory users.
    This will allow you to restrict access to the artifactory server for users blocked in LDAP.

    """

    ## Get value from file Will be removed  ##
    with open('.settings', 'r') as f:
        config = json.load(f)

    # LDAP vars override with config file values
    LDAP_USER = config['ldap_username']
    LDAP_PASSWORD = base64.b64decode(config['ldap_password']).decode().strip()

    # Artifactory vars override with config file values
    main_url = config['artifactory_url']
    ARTIFACTORY_USER = config['artifactory_user']
    ARTIFACTORY_TOKEN = base64.b64decode(config['artifactory_token']).decode().strip()

    if check_availability(main_url) == 'OK':
        users = get_users_list(main_url,ARTIFACTORY_TOKEN).get('users')
        for user in users:
            state = 0
            if user['realm'] == 'saml' and user['status'] == 'enabled':
                try:
                    lusr = ldap_get_user(conn, LDAP_SERVER, LDAP_USER, LDAP_PASSWORD, LDAP_USER_TYPE, user['username'])
                    if lusr:
                        ldap_user = lusr['attributes']['uid'][0]
                        if lusr['attributes']['nsAccountLock']:
                            ldap_user_status = lusr['attributes']['nsAccountLock'][0]
                        else:
                            ldap_user_status = 'FALSE' 
                        if ldap_user_status == 'TRUE':
                            print('Account is locked: ' + ldap_user)
                            delete_user (main_url, ARTIFACTORY_TOKEN, ldap_user)
                        else:
                            print('Account is enadled: ' + ldap_user)
                    else:
                        print('Account is not found in LDAP: ' + user['username'])
                        delete_user (main_url, ARTIFACTORY_TOKEN, ldap_user)
                except Exception as e:
                    print('Error: '+ str(e))
                    raise

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print('Error: '+ str(e))
        raise