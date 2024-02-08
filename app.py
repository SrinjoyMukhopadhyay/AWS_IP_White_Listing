from flask import Flask, render_template, request

import boto3


app = Flask(__name__)


ec2_client = boto3.client('ec2')


security_group_id_1 = 'sg-0171e43f56edfab21' 
security_group_id_2= 'sg-0004ad0fb4d71c4e1'

def get_security_group_rules_1():
    try:
        response = ec2_client.describe_security_groups(GroupIds=[security_group_id_1])
        security_group = response['SecurityGroups'][0]
        inbound_rules = security_group.get('IpPermissions', [])
        return inbound_rules
    except Exception as e:
        print(f"Error fetching security group rules: {e}")
        return []
def get_security_group_rules_2():
    try:
        response = ec2_client.describe_security_groups(GroupIds=[security_group_id_2])
        security_group = response['SecurityGroups'][0]
        inbound_rules = security_group.get('IpPermissions', [])
        return inbound_rules
    except Exception as e:
        print(f"Error fetching security group rules: {e}")
        return []

def get_existing_ip_port_pairs_1():
    response = ec2_client.describe_security_groups(GroupIds=[security_group_id_1])
    ip_permissions = response['SecurityGroups'][0]['IpPermissions']
    ip_port_pairs = []
    for permission in ip_permissions:
        ip_protocol = permission.get('IpProtocol')
        from_port = permission.get('FromPort')
        to_port = permission.get('ToPort')
        for ip_range in permission.get('IpRanges', []):
            cidr_ip = ip_range['CidrIp']
            ip_port_pairs.append((cidr_ip, ip_protocol, from_port, to_port))
    return ip_port_pairs
def get_existing_ip_port_pairs_2():
    response = ec2_client.describe_security_groups(GroupIds=[security_group_id_2])
    ip_permissions = response['SecurityGroups'][0]['IpPermissions']
    ip_port_pairs = []
    for permission in ip_permissions:
        ip_protocol = permission.get('IpProtocol')
        from_port = permission.get('FromPort')
        to_port = permission.get('ToPort')
        for ip_range in permission.get('IpRanges', []):
            cidr_ip = ip_range['CidrIp']
            ip_port_pairs.append((cidr_ip, ip_protocol, from_port, to_port))
    return ip_port_pairs

@app.route('/', methods=['GET', 'POST'])
def index():
    existing_ip_port_pairs_1 = get_existing_ip_port_pairs_1()
    existing_ip_port_pairs_2 = get_existing_ip_port_pairs_2()
    if request.method == 'POST':
        ip_address = request.form['ip_address']
        action = request.form['action']
        port=request.form['protocol']
        if port=="rdp":
            port=3389
        elif port=="ssh":
            port=22
        server=request.form['security_group']
        try:
            if server=="server-1":
                if action == 'add':
                    response = ec2_client.authorize_security_group_ingress(
                        GroupId=security_group_id_1,
                        IpPermissions=[
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': port,
                                'ToPort': port,
                                'IpRanges': [
                                    {
                                        'CidrIp': ip_address + '/32'
                                    },
                                ],
                            },
                        ]
                        )
                    message = "IP address added successfully"
                elif action == 'remove':
                    response = ec2_client.revoke_security_group_ingress(
                        GroupId=security_group_id_1,
                        IpPermissions=[
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': port,  
                                'ToPort': port,  
                                'IpRanges': [
                                     {
                                         'CidrIp': ip_address + '/32'
                                     },
                                ],
                            },
                        ]
                        )
                    message = "IP address removed successfully"
                existing_ip_port_pairs_1 = get_existing_ip_port_pairs_1()
            elif server=="server-2":
                if action == 'add':
                    response = ec2_client.authorize_security_group_ingress(
                        GroupId=security_group_id_2,
                        IpPermissions=[
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': port,
                                'ToPort': port,
                                'IpRanges': [
                                    {
                                        'CidrIp': ip_address + '/32'
                                    },
                                ],
                            },
                        ]
                        )
                    message = "IP address added successfully"
                elif action == 'remove':
                    response = ec2_client.revoke_security_group_ingress(
                        GroupId=security_group_id_2,
                        IpPermissions=[
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': port,  
                                'ToPort': port,  
                                'IpRanges': [
                                     {
                                         'CidrIp': ip_address + '/32'
                                     },
                                ],
                            },
                        ]
                        )
                    message = "IP address removed successfully"
                existing_ip_port_pairs_2 = get_existing_ip_port_pairs_2()
            
        except Exception as e:
            message = f"Error: Invalid IP address format"
        return render_template('index.html', message=message, existing_ip_port_pairs_1=existing_ip_port_pairs_1, existing_ip_port_pairs_2=existing_ip_port_pairs_2)
    
    return render_template('index.html', existing_ip_port_pairs_1=existing_ip_port_pairs_1, existing_ip_port_pairs_2=existing_ip_port_pairs_2)

@app.route('/view_1')
def view_1():
    security_group_rules = get_security_group_rules_1()
    return render_template('view_1.html', security_group_rules=security_group_rules)
@app.route('/view_2')
def view_2():
    security_group_rules = get_security_group_rules_2()
    return render_template('view_2.html', security_group_rules=security_group_rules)
    

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
    
