import json, os, boto3

# from botocore.vendored import requests

iam_client = boto3.client('iam')
iam_resource = boto3.resource('iam')

sts_client = boto3.client('sts')


def AttachPermission(role_name='', permission='', iam_policy_json=''):
    valid_permissions = ['IAMPolicyJSON', 'AssumeRoleS3', 'AssumeRoleEC2']

    assert permission in valid_permissions, print('Valid Permissions:', valid_permissions)

    if permission == 'IAMPolicyJSON':
        policy_name = iam_policy_json['Statement'][0]['Sid'][:-1]
        response = iam_client.put_role_policy(RoleName=role_name, PolicyName=policy_name,
                                              PolicyDocument=json.dumps(iam_policy_json))
        print('[AttachPermission]', response)

        return response


def GetIAMRole(role_name='', user_id=''):
    if len(user_id) > 0:
        role_name = 'irene@%s' % user_id
    elif len(role_name) == 0:
        return None

    try:  # check requested role existence
        response = iam_client.get_role(RoleName=role_name)

        arn = response['Role']['Arn']
        role_name = response['Role']['RoleName']
        role_id = response['Role']['RoleId']
    except iam_client.exceptions.NoSuchEntityException:
        return None

    return {
        'arn': arn, 'role_name': role_name, 'role_id': role_id
    }


def GetAllIAMRolePolicies(role_name='', user_id=''):
    if len(user_id) > 0:
        role_name = 'irene@%s' % user_id
    elif len(role_name) == 0:
        return None

    role = iam_resource.Role(role_name)
    return role.policies.all()


def DeleteAllIreneManagedIAMRolePolicies(role_name='', user_id=''):
    if len(user_id) > 0:
        role_name = 'irene@%s' % user_id
    elif len(role_name) == 0:
        return None

    role_policies = GetAllIAMRolePolicies(user_id=user_id)

    for role_policy in role_policies:
        print('POLICY NAME', role_policy.policy_name)
        if role_policy.policy_name.startswith('irene'):
            print('deletion requested policy name', role_policy.policy_name)
            role_policy.delete()

    for managed_policy_arn in ['arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore']:
        try:
            managed_policy = iam_resource.Policy(managed_policy_arn)
            print('detach requested managed policy name', managed_policy.policy_name)
            managed_policy.detach_role(RoleName=role_name)
        except iam_client.exceptions.NoSuchEntityException:
            print('[NoSuchEntityException]', managed_policy_arn)

    ''' Detach & Delete Instance Profile '''
    try:
        response = iam_client.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    except iam_client.exceptions.NoSuchEntityException:
        print('[iam_client.remove_role_from_instance_profile(): NoSuchEntityException]', role_name)

    try:
        response = iam_client.delete_instance_profile(InstanceProfileName=role_name)
    except iam_client.exceptions.NoSuchEntityException:
        print('[iam_client.delete_instance_profile(): NoSuchEntityException]', role_name)


def GetIAMPolicyJSON(description):
    rule_name = description['rule_name']

    if rule_name in ['S3 Bucket - Read', 'S3 Bucket - Write', 'S3 Bucket - Full']:
        with open('permissions/templates/template_{rule_name}.json'.format(rule_name=rule_name), 'r') as fin:
            rule_template_raw = fin.read()
            rule_template_raw = rule_template_raw.replace('{alphanumeric_bucket_name}', description['bucket_name'].replace('-', '').replace('_', '').replace('/', '').replace(' ', ''))  # for Sid
            rule_template_raw = rule_template_raw.replace('{bucket_name}', description['bucket_name'])
            iam_policy_json = json.loads(rule_template_raw)

        return iam_policy_json

    if rule_name in ['Glue - Basic']:
        with open('permissions/templates/template_{rule_name}.json'.format(rule_name=rule_name), 'r') as fin:
            rule_template_raw = fin.read()
            rule_template_raw = rule_template_raw.replace('{region_name}', description['region_name'])
            rule_template_raw = rule_template_raw.replace('{aws_account_id}', description['aws_account_id'])
            iam_policy_json = json.loads(rule_template_raw)

        return iam_policy_json

    if rule_name in ['Glue - Write', 'Glue - Full']:
        database_name = description['bucket_name'].strip('/').split('/')[-1]

        with open('permissions/templates/template_{rule_name}.json'.format(rule_name=rule_name), 'r') as fin:
            rule_template_raw = fin.read()
            rule_template_raw = rule_template_raw.replace('{alphanumeric_bucket_name}', description['bucket_name'].replace('-', '').replace('_', '').replace('/', '').replace(' ', ''))  # for Sid
            # rule_template_raw = rule_template_raw.replace('{bucket_name}', description['bucket_name'])
            rule_template_raw = rule_template_raw.replace('{database_name}', database_name)
            rule_template_raw = rule_template_raw.replace('{region_name}', description['region_name'])
            rule_template_raw = rule_template_raw.replace('{aws_account_id}', description['aws_account_id'])
            iam_policy_json = json.loads(rule_template_raw)

        return iam_policy_json

    if rule_name in ['WIND - Read']:
        with open('permissions/templates/template_{rule_name}.json'.format(rule_name=rule_name), 'r') as fin:
            rule_template_raw = fin.read()
            iam_policy_json = json.loads(rule_template_raw)

        return iam_policy_json


def AppendOrReplaceIAMRolePolicy(permission_document, mode):
    if mode.upper() not in ['REPLACE', 'APPEND']:
        print('mode must be either REPLACE or APPEND.')
        return None

    if mode.upper() == 'REPLACE':
        delete_requested_user_ids = set()
        for permission_description in permission_document:
            for user_id in permission_description['user_id']:
                delete_requested_user_ids.add(user_id)

        for user_id in delete_requested_user_ids:
            print('Request DeleteAllIreneManagedRolePolicies', user_id)
            DeleteAllIreneManagedIAMRolePolicies(user_id=user_id)

    failure_messages = list()
    for permission_description in permission_document:
        print(permission_description)

        ''' Handle S3 Permission '''
        if permission_description['resource'].startswith('s3:'):
            bucket_name = permission_description['resource'].split('s3:')[-1]
            rule_name = 'S3 Bucket - %s' % permission_description['permission']

            for user_id in permission_description['user_id']:
                user_iam_role = GetIAMRole(user_id=user_id)
                role_name = user_iam_role['role_name']
                arn = user_iam_role['arn']

                print('s3', rule_name, bucket_name, user_id, role_name, arn)

                iam_policy_json = GetIAMPolicyJSON({'rule_name': rule_name, 'bucket_name': bucket_name})
                if iam_policy_json:
                    AttachPermission(role_name=role_name, permission='IAMPolicyJSON', iam_policy_json=iam_policy_json)
                else:
                    print('failed to attach s3 permission:', rule_name, user_id, role_name)
                    failure_messages.append('failed to attach permission: rule_name %s, user_id %d, role_name %s' % (
                        rule_name, user_id, role_name
                    ))

                ''' Write or Full Permission also requires Glue Permission'''
                if permission_description['permission'] in ['Write', 'Full']:
                    print('glue', 'Glue - %s' % permission_description['permission'], bucket_name, user_id, role_name, arn)

                    iam_policy_json = GetIAMPolicyJSON(
                        {'rule_name': 'Glue - %s' % permission_description['permission'], 'bucket_name': bucket_name, 'aws_account_id': arn.split(':')[4], 'region_name': 'ap-northeast-2'})
                    if iam_policy_json:
                        AttachPermission(role_name=role_name, permission='IAMPolicyJSON', iam_policy_json=iam_policy_json)
                    else:
                        print('failed to attach glue permission:', 'Glue - %s' % permission_description['permission'], user_id, role_name)
                        failure_messages.append('failed to attach permission: rule_name %s, user_id %d, role_name %s' % (
                            'Glue - %s' % permission_description['permission'], user_id, role_name
                        ))

        ''' Handle WIND Permission '''
        if permission_description['resource'] == 'WIND':
            rule_name = 'WIND - %s' % permission_description['permission']

            for user_id in permission_description['user_id']:
                user_iam_role = GetIAMRole(user_id=user_id)
                role_name = user_iam_role['role_name']
                # arn = user_iam_role['arn']

                print(rule_name, user_id, role_name)
                iam_policy_json = GetIAMPolicyJSON({'rule_name': rule_name})
                if iam_policy_json:
                    AttachPermission(role_name=role_name, permission='IAMPolicyJSON', iam_policy_json=iam_policy_json)
                else:
                    print('failed to attach permission:', rule_name, user_id, role_name)
                    failure_messages.append('failed to attach permission: rule_name %s, user_id %d, role_name %s' % (
                        rule_name, user_id, role_name
                    ))

    return {'failure_messages': failure_messages}


def DeleteIAMRolePolicy(permission_document):
    failure_messages = list()
    for permission_description in permission_document:
        print(permission_description)

        ''' Handle S3 Permission '''
        if permission_description['resource'].startswith('s3:'):
            bucket_name = permission_description['resource'].split('s3:')[-1]
            rule_name = 'S3 Bucket - %s' % permission_description['permission']

            for user_id in permission_description['user_id']:
                user_iam_role = GetIAMRole(user_id=user_id)
                role_name = user_iam_role['role_name']
                arn = user_iam_role['arn']

                print('s3', rule_name, bucket_name, user_id, role_name)
                iam_policy_json = GetIAMPolicyJSON({'rule_name': rule_name, 'bucket_name': bucket_name})
                if iam_policy_json:
                    policy_name = iam_policy_json['Statement'][0]['Sid'][:-1]
                    print('delete IAM Role Policy for s3:', policy_name)
                    role_policy = iam_resource.RolePolicy(role_name, policy_name)
                    try:
                        role_policy.delete()
                    except iam_client.exceptions.NoSuchEntityException:
                        pass
                else:
                    print('failed to delete s3 permission:', rule_name, user_id, role_name)
                    failure_messages.append('failed to delete s3 permission: rule_name %s, user_id %d, role_name %s' % (
                        rule_name, user_id, role_name
                    ))

                ''' Write or Full Permission also requires Glue Permission'''
                if permission_description['permission'] in ['Write', 'Full']:
                    print('glue', rule_name, bucket_name, user_id, role_name, arn)

                    iam_policy_json = GetIAMPolicyJSON(
                        {'rule_name': 'Glue - %s' % permission_description['permission'], 'bucket_name': bucket_name, 'aws_account_id': arn.split(':')[4], 'region_name': 'ap-northeast-2'})
                    if iam_policy_json:
                        policy_name = iam_policy_json['Statement'][0]['Sid'][:-1]
                        print('delete IAM Role Policy for glue:', policy_name)
                        role_policy = iam_resource.RolePolicy(role_name, policy_name)
                        try:
                            role_policy.delete()
                        except iam_client.exceptions.NoSuchEntityException:
                            pass
                    else:
                        print('failed to delete glue permission:', rule_name, user_id, role_name)
                        failure_messages.append('failed to delete glue permission: rule_name %s, user_id %d, role_name %s' % (
                            rule_name, user_id, role_name
                        ))

        ''' Handle WIND Permission '''
        if permission_description['resource'] == 'WIND':
            rule_name = 'WIND - %s' % permission_description['permission']

            for user_id in permission_description['user_id']:
                role_name = GetIAMRole(user_id=user_id)['role_name']

                print(rule_name, user_id, role_name)
                iam_policy_json = GetIAMPolicyJSON({'rule_name': rule_name})
                if iam_policy_json:
                    policy_name = iam_policy_json['Statement'][0]['Sid'][:-1]

                    role_policy = iam_resource.RolePolicy(role_name, policy_name)
                    try:
                        role_policy.delete()
                    except iam_client.exceptions.NoSuchEntityException:
                        pass
                else:
                    print('failed to delete permission:', rule_name, user_id, role_name)
                    failure_messages.append('failed to attach permission: rule_name %s, user_id %d, role_name %s' % (
                        rule_name, user_id, role_name
                    ))

    return {'failure_messages': failure_messages}


def CreateIAMRole(user_id):
    role_name = 'irene@%s' % user_id

    try:  # check requested role exsistance
        response = iam_client.get_role(RoleName=role_name)
    except iam_client.exceptions.NoSuchEntityException:
        if os.path.exists('permissions/assumerole_s3,ec2,lambda,skn-lambda-user.json'):
            with open('permissions/assumerole_s3,ec2,lambda,skn-lambda-user.json', 'r') as fin:
                assume_role_policy_document = json.load(fin)
        else:
            print('Cannot create IAMRole: assumerole_s3,ec2,lambda,skn-lambda-user.json does not exist.')
            raise

        response = iam_client.create_role(RoleName=role_name,
                                          AssumeRolePolicyDocument=json.dumps(assume_role_policy_document),
                                          MaxSessionDuration=43200)

    arn = response['Role']['Arn']
    role_name = response['Role']['RoleName']
    role_id = response['Role']['RoleId']

    ''' Attach Managed Policies '''
    iam_client.attach_role_policy(RoleName=role_name, PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore')  # AmazonSSMManagedInstanceCore

    ''' Attach Glue Basic Permission '''
    iam_policy_json = GetIAMPolicyJSON({'rule_name': 'Glue - Basic', 'aws_account_id': arn.split(':')[4], 'region_name': 'ap-northeast-2'})
    if iam_policy_json:
        AttachPermission(role_name=role_name, permission='IAMPolicyJSON', iam_policy_json=iam_policy_json)

    ''' '''
    try:
        response = iam_client.create_instance_profile(InstanceProfileName=role_name)
    except iam_client.exceptions.EntityAlreadyExistsException:
        response = 'EntityAlreadyExists'

    try:
        response = iam_client.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    except iam_client.exceptions.LimitExceededException:
        response = 'ProfileAlreadyAttached'

    return {
        'arn': arn, 'role_name': role_name, 'role_id': role_id
    }


def GetIAMRole(user_id):
    role_name = 'irene@%s' % user_id

    arn = 'NoSuchEntity'
    role_id = 'NoSuchEntity'

    try:
        response = iam_client.get_role(RoleName=role_name)
        arn = response['Role']['Arn']
        role_name = response['Role']['RoleName']
        role_id = response['Role']['RoleId']
    except iam_client.exceptions.NoSuchEntityException:
        role_name = 'NoSuchEntity'

    return {
        'arn': arn, 'role_name': role_name, 'role_id': role_id
    }


def PurgeIAMRole(user_id):
    role_name = 'irene@%s' % user_id

    failure_messages = list()

    try:  # check requested role exsistance
        response = iam_client.get_role(RoleName=role_name)
    except iam_client.exceptions.NoSuchEntityException:
        response = None
        failure_messages.append('[iam_client.get_role(): NoSuchEntityException] user_id: %s, expected RoleName: %s' % (user_id, role_name))

    try:  # check requested role exsistance
        DeleteAllIreneManagedIAMRolePolicies(user_id=user_id)
    except iam_client.exceptions.NoSuchEntityException:
        response = None
        failure_messages.append('[DeleteAllIreneManagedIAMRolePolicies(): NoSuchEntityException] user_id: %s, expected RoleName: %s' % (user_id, role_name))

    try:  # check requested role exsistance
        response = iam_client.delete_role(RoleName=role_name)
    except iam_client.exceptions.NoSuchEntityException:
        response = None
        failure_messages.append('[iam_client.delete_role(): NoSuchEntityException] user_id: %s, expected RoleName: %s' % (user_id, role_name))

    return {
        'response': response,
        'failure_messages': failure_messages
    }


def lambda_handler(event, context):
    print(event)
    # context = event.get('context', {})

    # print(context.get('http-method', ''))
    # if context.get('http-method', '') != 'POST':
    #     return {
    #         'statusCode': 503
    #     }

    body = event.get('body-json', {})
    action = body.get('action', {})
    print(action)

    if action.upper() == 'CREATE':
        user_id = body.get('user_id', {})
        response = CreateIAMRole(user_id)
    elif action.upper() == 'GET':
        user_id = body.get('user_id', {})
        response = GetIAMRole(user_id)
    elif action.upper() == 'PURGE':
        user_id = body.get('user_id', {})
        response = PurgeIAMRole(user_id)
    elif action.upper() == 'REPLACE':
        permission_document = body.get('permission_document', {})
        response = AppendOrReplaceIAMRolePolicy(permission_document, mode='REPLACE')
    elif action.upper() == 'APPEND':
        permission_document = body.get('permission_document', {})
        response = AppendOrReplaceIAMRolePolicy(permission_document, mode='APPEND')
    elif action.upper() == 'DELETE':
        permission_document = body.get('permission_document', {})
        response = DeleteIAMRolePolicy(permission_document)
    elif action.upper() == 'TEST':
        pass
    else:
        response = {
            'error_status': 'invalid action, action must be one of the `CREATE`, `REPLACE`, `APPEND`, `DELETE` (case-insensitive)'}

    return {
        'statusCode': 200,
        'body': json.dumps(response)
    }
