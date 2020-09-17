#########################
#    Work in progress   #
#########################

import boto3
import json
import os
from datetime import datetime, timedelta, date
from dateutil import parser
from botocore.exceptions import ClientError
from collections import namedtuple
import time

# initialize IAM connection
resource = boto3.resource('iam')
client = boto3.client("iam")

# custom log stream
logs = boto3.client('logs')
try:
    logs.create_log_group(logGroupName='disable-inactive-unused-iam')
except Exception as e:
    print(e)
try:
    logs.create_log_stream(logGroupName='disable-inactive-unused-iam', logStreamName='user')
except Exception as e:
    print(e)
try:
    logs.create_log_stream(logGroupName='disable-inactive-unused-iam', logStreamName='key')
except Exception as e:
    print(e)

# user tuple format
User = namedtuple('User', 'user arn user_creation_time password_enabled password_last_used password_last_changed password_next_rotation mfa_active access_key_1_active access_key_1_last_rotated access_key_1_last_used_date access_key_1_last_used_region access_key_1_last_used_service access_key_2_active access_key_2_last_rotated access_key_2_last_used_date access_key_2_last_used_region access_key_2_last_used_service cert_1_active cert_1_last_rotated cert_2_active cert_2_last_rotated')

def lambda_handler(event, context):
    # generate report 
    response = client.generate_credential_report()
    
    while response['State'] != 'COMPLETE':
        time.sleep(2)
    
    # format report to readable
    response = client.get_credential_report()
    body = response['Content'].decode('utf-8')
    lines = body.split('\n')
    users = [User(*line.split(',')) for line in lines[1:]]
    
    # current Datetime
    today = datetime.now()
    
    # initialize lists
    never_logged_in_user = []            # console user
    inactive_past_90_days_user = []      # console user
    never_used_key = []                  # access key user
    inactive_past_90_days_key = []       # access key user
    
    for user in users:
        # user has access privilege to web aws console
        if user.password_enabled == 'true':
            
            # user used their password at least one time
            if (user.password_last_used != 'N/A' and user.password_last_used != 'no_information'):
                
                # convert string to datetime
                temp_user_password_last_used = parser.parse(user.password_last_used)
                delta = (today - temp_user_password_last_used.replace(tzinfo=None)).days
                
                # check if user dont logged in for the past 90 days
                if delta >= 90:
                    inactive_past_90_days_user.append({
                        'username': user.user,
                        'inactivity_time': delta
                    })
                    
            # user never used password (never made login)
            else:
                never_logged_in_user.append({
                        'username': user.user
                    })
            
        #########################  
        # user has only api keys
        else:
            # check if access key 1 is active
            if user.access_key_1_active == 'true':
                
                # user used this key at least one time
                try:
                    # convert string to datetime
                    temp_user_password_last_used = parser.parse(user.access_key_1_last_used_date)
                    delta = (today - temp_user_password_last_used.replace(tzinfo=None)).days
                    
                    # check if user dont logged in for the past 90 days
                    if delta >= 90:
                        inactive_past_90_days_key.append({
                            'username': user.user,
                            'key': '1',
                            'inactivity_time': delta
                        })
                        
                except:
                    never_used_key.append({
                        'username': user.user,
                        'key': '1'
                    })
                    
            # check if access key 1 is active
            if user.access_key_2_active == 'true':
                
                # user used this key at least one time
                try:
                    # convert string to datetime
                    temp_user_password_last_used = parser.parse(user.access_key_2_last_used_date)
                    delta = (today - temp_user_password_last_used.replace(tzinfo=None)).days
                    
                    # check if user dont logged in for the past 90 days
                    if delta >= 90:
                        inactive_past_90_days_key.append({
                            'username': user.user,
                            'key': '2',
                            'inactivity_time': delta
                        })
                        
                except:
                    never_used_key.append({
                        'username': user.user,
                        'key': '2'
                    })
                

    # Log to lambda cloudwatch operational info
    print('inactive_past_90_days_user\t', inactive_past_90_days_user)
    print('never_logged_in_user\t', never_logged_in_user)
    print('inactive_past_90_days_key\t', inactive_past_90_days_key)
    print('never_used_key\t', never_used_key)
    
    for user in inactive_past_90_days_user:
        str_aux = str(user['username']) + '\t' + 'disable_console_access'
        str_aux += '\t' + str(user['inactivity_time']) + '\tdays_inactive'
        try:
            # remove the login_profile/password/ability to use the Console
            client.delete_login_profile(UserName=user['username'])
            str_aux = 'SUCCESS\t' + str_aux
            create_log_cloudwatch(str_aux, 'user')
        except Exception as e:
            # error to remove ability to use console
            str_aux = 'ERROR\t' + str_aux
            create_log_cloudwatch(str_aux, 'user')
            print(e)
    
    for user in never_logged_in_user:
        str_aux = str(user['username']) + '\t' + 'disable_console_access'
        try:
            # remove the login_profile/password/ability to use the Console
            client.delete_login_profile(UserName=user['username'])
            str_aux = 'SUCCESS\t' + str_aux
            create_log_cloudwatch(str_aux, 'user')
        except Exception as e:
            # error to remove ability to use console
            str_aux = 'ERROR\t' + str_aux
            create_log_cloudwatch(str_aux, 'user')
            print(e)
            
    
    # Delete unused access keys        
    timeLimit = datetime.now() - timedelta( days = int(90) )
    concat_list_key = inactive_past_90_days_key + never_used_key
    deleted_access_key = []
    for user in concat_list_key:
        try:
            accessKeys = client.list_access_keys(UserName=user['username'])
            # Iterate over the keys
            for key in accessKeys['AccessKeyMetadata']:
                if key['CreateDate'].date() <= timeLimit.date():
                    
                    str_aux = str(user['username']) + '\tdisable_access_key\t' + str(key['AccessKeyId']) + '\t' + str((date.today() - key['CreateDate'].date()).days) + '\t' +str('key_age')
                    if 'inactivity_time' in user:
                        str_aux += '\t' + str(user['inactivity_time']) + '\tdays_inactive'
                    
                    try:
                        # remove the access key
                        response = client.delete_access_key(
                            AccessKeyId=key['AccessKeyId'],
                            UserName=user['username'],
                        )
                        str_aux = 'SUCCESS\t' + str_aux
                        create_log_cloudwatch(str_aux, 'key')
                    except Exception as e:
                        # error to remove ability to use console
                        str_aux = 'ERROR\t' + str(e) + '\t' + str_aux
                        create_log_cloudwatch(str_aux, 'key')
                        print(e)
        except:
            pass
        
    
    # delete users without login and at least one key
    for user in users:
        if user.password_enabled == 'false' or user.password_enabled == 'N/A':
            if user.access_key_1_active == 'false' or user.access_key_1_active == 'N/A':
                if user.access_key_2_active == 'false' or user.access_key_2_active == 'N/A':
                    
                    # detach attached policies
                    try:
                        policies = client.list_attached_user_policies(
                            UserName=user.user
                        )
                        for policy in policies['AttachedPolicies']:
                            try:
                                response = client.detach_user_policy(
                                    UserName=user.user,
                                    PolicyArn=policy['PolicyArn']
                                )
                                str_aux = 'INFO\t' + str(user.user) + '\tdetach_policy' + str(policy['PolicyArn'])
                                create_log_cloudwatch(str_aux, 'user')
                                print(str_aux)
                            except Exception as e:
                                str_aux = 'ERROR\t' + str(e) + '\t' + str(user.user) + '\tdetach_policy\t' + str(policy['PolicyArn'])
                                print(str_aux)
                    except Exception as e:
                        str_aux = 'ERROR\t' + str(e) + '\t' + str(user.user) + '\tlist_policy'
                        # create_log_cloudwatch(str_aux, 'user')
                        # print(str_aux)
                        print(str_aux)
                        
                    
                    # detach user groups
                    try:
                        groups = client.list_groups_for_user(
                            UserName=user.user
                        )
                        for group in groups['Groups']:
                            try:
                                response = client.remove_user_from_group(
                                    GroupName=group['GroupName'],
                                    UserName=user.user
                                )
                                str_aux = 'INFO\t' + str(user.user) + '\tremove_user_from_group\t' + str(group['GroupName'])
                                create_log_cloudwatch(str_aux, 'user')
                                print(str_aux)
                            except Exception as e:
                                str_aux = 'ERROR\t' + str(e) + '\t' + str(user.user) + '\tremove_user_from_group\t' + str(group['GroupName'])
                                print(str_aux)
                    except Exception as e:
                        str_aux = 'ERROR\t' + str(e) + '\t' + str(user.user) + '\tlist_groups'
                        # create_log_cloudwatch(str_aux, 'user')
                        # print(str_aux)
                        print(str_aux)
                        
                    
                    # remove user policies
                    try:
                        policies = client.list_user_policies(
                            UserName=user.user
                        )
                        for policy in policies['PolicyNames']:
                            try:
                                response = client.delete_user_policy(
                                    UserName=user.user,
                                    PolicyName=policy
                                )
                                str_aux = 'INFO\t' + str(user.user) + '\tdetach_policy_user' + str(policy)
                                create_log_cloudwatch(str_aux, 'user')
                                print(str_aux)
                            except Exception as e:
                                str_aux = 'ERROR\t' + str(e) + '\t' + str(user.user) + '\tdetach_policy_user\t' + str(policy)
                                print(str_aux)
                    except Exception as e:
                        str_aux = 'ERROR\t' + str(e) + '\t' + str(user.user) + '\tlist_policy_user'
                        # create_log_cloudwatch(str_aux, 'user')
                        # print(str_aux)
                        print(str_aux)
                    
                    
                    str_aux = str(user.user) + '\tusername_deleted'
                    try:
                        response = client.delete_user(
                            UserName=user.user
                        )
                        str_aux = 'SUCCESS\t' + str_aux
                        create_log_cloudwatch(str_aux, 'user')
                        print(str_aux)
                    except Exception as e:
                        # error to remove user
                        str_aux = 'ERROR\t' + str(e) + '\t' + str_aux
                        create_log_cloudwatch(str_aux, 'user')
                        print(str_aux)
                        print(e)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Function executed successfully",
        }),
    }
    

def create_log_cloudwatch(message, log_stream_name):
    logs = boto3.client('logs')
    
    response = logs.describe_log_streams(
        logGroupName='disable-inactive-unused-iam',
        logStreamNamePrefix=log_stream_name
    )
    
    event_log = {
    	'logGroupName': 'disable-inactive-unused-iam',
    	'logStreamName': log_stream_name,
    	'logEvents': [{
    		'timestamp': int(round(time.time() * 1000)),
    		'message': message
    	}],
    }
    
    if 'uploadSequenceToken' in response['logStreams'][0]:
        event_log.update({'sequenceToken': response['logStreams'][0] ['uploadSequenceToken']})

    response = logs.put_log_events(**event_log)
