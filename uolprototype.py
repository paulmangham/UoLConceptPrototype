import boto3
from botocore.exceptions import ClientError
import os
import pprint
import json
import datetime


def selectComplianceOption():

    # User menu rendering
    os.system('clear')
    print("Select compliance standard")
    print("--------------------------\n")
    complianceItems = ["PCIDSS","HIPAA","NOSPEC"]
    for item in complianceItems:
        print("[" + str(complianceItems.index(item)) + "] " + item)
    backMenuNumber = (len(complianceItems))
    print("[" + str(backMenuNumber) + "] Back to main menu\n")
    choice = input("Please select a compliance option: ")

    # Process and return menu selection
    if int(choice) == backMenuNumber:
        main()
    else:
        return(complianceItems[int(choice)])



def createCompliantInstance():
    ### Acquire the compliance requirements from the user
    complianceChoice = selectComplianceOption()

    ### Get a dictionary version of the compliance requirements
    complianceSpec = getComplianceSpec(complianceChoice)

    # Initialise compliance requirement variables
    diskEncryptionRequired = False
    ipsecRequired = False
    hostFirewallRequired = False

    ### CSA CCM Control ID IVS-10 relates to disk encryption
    if complianceSpec["IVS-10"] == "True":
        diskEncryptionRequired = True

    ### CSA CCM Control ID DSI-03 relates to network encryption
    if complianceSpec["DSI-03"] == "True":
        ipsecRequired = True

    ### CSA CCM Control IDs IVS-06 and IVS-08 related to firewall requirements
    if complianceSpec["IVS-06"] == "True" or complianceSpec["IVS-08"] == "True":
        hostFirewallRequired = True
    
    # Notify user of technical security requirements for this compliance standard
    os.system('clear')
    securityMenuHeading = "Security requirements of " + complianceChoice + " for instance creation"
    print(securityMenuHeading)
    print("-" * len(securityMenuHeading) + "\n")

    if diskEncryptionRequired:
        print(u"\u2022 Local disk encryption is required for this instance.\n" +
            "  Ensure you enter an ami-id of an encrypted image when prompted.\n")
    else:
        print(u"\u2022 Local disk encryption is not required.\n")

    if ipsecRequired:
        print(u"\u2022 Local network encryption (IPSec) is required.\n" +
            "  Ensure IPSec is enabled on the Amazon Machine Image's Operating System.\n")
    else:
        print(u"\u2022 Local network encryption (IPSec) is not required.\n")
    
    if hostFirewallRequired:
        print(u"\u2022 A host-based firewall is required.\n" + 
            "  A Security Group will be created with restricted access rules.\n")
    else:
        print(u"\u2022 A host-based firewall is not required.\n" + 
            "  The instance will be created in the default Security Group.\n")

    input("Press return to continue")
    
    os.system('clear')

    ### Acquire the ID of the Amazon Machine Image to use to create this instance
    amiId = getAmiId(diskEncryptionRequired, ipsecRequired)

    ### Generate a unique name for the instance and, if necessary, Security Group
    now = datetime.datetime.now()
    isotime = now.isoformat()
    instanceName = str(complianceChoice + "_" + isotime)
    executeInstanceCreation(amiId, instanceName, hostFirewallRequired)



def executeInstanceCreation(amiId, instanceName, hostFirewallRequired):

    ### Confirm creation request and display details
    execute = input("Are you sure you wish to create this instance? (Y\\N) ")
    if execute.upper() == "Y":
        os.system('clear')
        print("Issuing instance creation instruction to AWS.")
        print("AMI ID: " + amiId)
        print("Name: " + instanceName)

        ec2_resource = boto3.resource('ec2')

        if not hostFirewallRequired:
            print("Instance will be created in default Security Group")
            ### Create instance in default Security Group
            newInstance = ec2_resource.create_instances(ImageId=amiId, MinCount=1, MaxCount=1,
                                    InstanceType='t2.micro', TagSpecifications=[
                                                                    {
                                                                        'ResourceType': 'instance',
                                                                        'Tags': [
                                                                            {
                                                                                'Key': 'Name',
                                                                                'Value': instanceName
                                                                            },
                                                                        ]
                                                                    },
                                                                ])
        else:
            ### Create a new, restricted access Security Group
            ### Then create the instance and assign it to the new Security Group

            ec2_client = boto3.client('ec2')
            response = ec2_client.create_security_group(GroupName=instanceName,
                                                    Description='Created by compliance prototype')

            securityGroupId = response['GroupId']
            print("New Security Group ID: " + securityGroupId)

            ### Assign arbitrary ingress rules to demonstrate usage
            ec2_client.authorize_security_group_ingress(
                GroupId = securityGroupId,
                IpPermissions=[
                    {'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges':[{'CidrIp': '172.31.16.0/20'}]},
                    {'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges':[{'CidrIp': '172.31.16.0/20'}]}
                ])

            ### Create instance in new security group
            newInstance = ec2_resource.create_instances(ImageId=amiId, MinCount=1, MaxCount=1,
                                    InstanceType='t2.micro', TagSpecifications=[
                                                                    {
                                                                        'ResourceType': 'instance',
                                                                        'Tags': [
                                                                            {
                                                                                'Key': 'Name',
                                                                                'Value': instanceName
                                                                            },
                                                                        ]
                                                                    },
                                                                ],
                                                                SecurityGroupIds=[securityGroupId])

        print("New Instance ID: " + newInstance[0].instance_id + "\n")
        input("Press return to go back to the main menu.")
        main()
    else:
        main()



def getAmiId(diskEncryptionRequired, ipsecRequired):

    # Inform the user of AMI requirements per compliance spec
    if diskEncryptionRequired and ipsecRequired:    
        print("Please enter the ami-id of an encrypted Amazon Machine Image which has \n" + 
            "IPSec enabled in the Operating System.\n")
    elif diskEncryptionRequired and not ipsecRequired:
        print("Please enter the ami-id of an encrypted Amazon Machine Image\n")
    elif not diskEncryptionRequired and ipsecRequired:
        print("Please enter the ami-id of an Amazon Machine Image with IPSec enabled " + 
            " in the Operating System\n")
    else:
        print("Please enter the ami-id of the image to use for this instance.\n")

    amiId = input("ami-id: ")

    client = boto3.client('ec2')
    response = client.describe_images(ImageIds=[amiId])

    ### Check if AMI is encrypted
    amiIsEncrypted = False
    if (response["Images"][0]["BlockDeviceMappings"][0]["Ebs"]["Encrypted"]) == True:
        amiIsEncrypted = True

    ### Check if AMI has IPSec enabled (by evaluating IPSec Tag)
    amiHasIpsec = False
    for image in response["Images"]:
        for tag in image["Tags"]:
            if tag["Key"] == "IPSec" and tag["Value"] == "True":
                amiHasIpsec = True

    ### Check requirements vs configuration of selected AMI
    if diskEncryptionRequired and ipsecRequired:
        if amiIsEncrypted and amiHasIpsec:
            print("\nAMI is validated with local drive encryption and an IPSec enabled Operating System.\n")
            return(amiId)
        else:
            print("\nThis AMI does not meet the requirements of the compliance standard.\n")
            input("Press return to continue.")
            os.system('clear')
            getAmiId(diskEncryptionRequired, ipsecRequired)
    elif diskEncryptionRequired and not ipsecRequired:
        if amiIsEncrypted:
            print("\nAMI is validated with local drive encryption.\n")
            return(amiId)
        else:
            print("\nThis AMI does not meet the requirements of the compliance standard.\n")
            input("Press return to continue.")
            os.system('clear')
            getAmiId(diskEncryptionRequired, ipsecRequired)
    elif not diskEncryptionRequired and ipsecRequired:
        if amiHasIpsec:
            print("\nAMI is validated with an IPSec enabled Operating System.\n")
            return(amiId)
        else:
            print("\nThis AMI does not meet the requirements of the compliance standard.\n")
            input("Press return to continue.")
            os.system('clear')
            getAmiId(diskEncryptionRequired, ipsecRequired)
    else:
        print("AMI is validated.\n")
        return(amiId)



def getComplianceSpec(compliance_required):
    
    ### Open the appropriate JSON document for the specified compliance standard
    if compliance_required == "PCIDSS":
        compliance_source = "csaccm_pcidss.json"
    elif compliance_required == "HIPAA":
        compliance_source = "csaccm_hipaa.json"
    elif compliance_required == "NOSPEC":
        compliance_source = "csaccm_nospec.json"
    else:
        return("ERROR: Unknown compliance spec")
    file = open(compliance_source)
    
    ### Check the file has opened for reading and read the contents into a variable
    if file.mode == 'r':
        fileContents = file.read()

    ### Parse the JSON data into a Python dictionary
    complianceSpec= json.loads(fileContents)
    
    ### Return the compliance specification to the caller
    return(complianceSpec)


def listRunningInstances():
    os.system('clear')
    print("Currently running instances")
    print("---------------------------\n")

    ec2_client = boto3.client('ec2')
    response = ec2_client.describe_instances()
    
    count = 0
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            if instance["State"]["Name"] == "running" or instance["State"]["Name"] == "initializing":
                count += 1
                for tag in instance["Tags"]:
                    if tag["Key"].upper() == "NAME":
                        print("Instance Name: " + tag["Value"])
                print("Instance ID: " + instance["InstanceId"])
                print("Public IP Address: " + instance["PublicIpAddress"] + "\n")

    print("Total number of running instances: " + str(count) + "\n")
    input("Press return to go back to the main menu")
    main()           




def main():
    # Initial menu display and main()
    rootMenuItems = [
        ["Create compliant instance", createCompliantInstance],
        ["List running instances", listRunningInstances],
        ["Exit", exit]
    ]
    while True:
        os.system('clear')
        print("Paul Mangham UoL Dissertation Project - Conceptual Prototype")
        print("------------------------------------------------------------\n")

        # Iterate through the rootMenuItems list, showing the index number within the
        # primary list as the menu number and the text of the first (0th) index
        # within each inner list as the menu text
        for item in rootMenuItems:
            print("[" + str(rootMenuItems.index(item)) + "] " + item[0])
        
        choice = input("\nPlease choose a menu item: ")

        # Basic input validation
        try:
            if int(choice) < 0 : raise ValueError
            # Call appropriate function
            rootMenuItems[int(choice)][1]()
            exit()
        except (ValueError, IndexError):
            pass

if __name__ == "__main__":
    main()

    

