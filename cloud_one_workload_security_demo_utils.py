import deepsecurity
from deepsecurity.rest import ApiException
import time
import platform
from subprocess import Popen, PIPE, STDOUT

# This file contains various functions that are re-used by the scripts

# This function will get the operating system where the tests are being run
# It returns the operating system
def getoperatingsystem():
    # Check the OS information
    platform_info = platform.platform()
    system_info = platform.system()
    release_info = platform.release()

    # If the platform is something other than what's been tested, exit
    if("ubuntu" not in platform_info.lower() and "redhat" not in platform_info.lower() and "windows" not in platform_info.lower()):
        print("Currently these tests only work on Ubuntu, Redhat and Windows.  Exiting!!")
        #exit()
    
    # Otherwise let's lowercase everything and return the operating system
    if("ubuntu" in platform_info.lower()):
        operating_system = "ubuntu"
    elif("redhat" in platform_info.lower()):
        operating_system = "redhat"
    elif("windows" in platform_info.lower()):
        operating_system = "windows"
    else:
        operating_system = "other"
    
    print("Platform is: " + operating_system)
    return(operating_system)

# This function gets the policies in the system
# It then prompts the user for what policy they want to use
# After the user seclects the policy, it gets the policy ID for that policy
# It returns the policy ID
def getpolicyid(configuration, api_version, overrides):
    # List the policies available and print them out so the user can choose
    available_policies = listpolicies(configuration, api_version, overrides)
    count = 1
    for policy in available_policies:
        print(str(count) + " = " + policy)
        count+=1
    policy_selected = False
    while(policy_selected == False):
        print("Enter the number for the policy you will be using for these tests?")
        selected_policy = input()
        if ((not selected_policy.isdigit()) or (int(selected_policy) > (len(available_policies)))):
            print("Invalid option, please try again")
        elif (int(selected_policy) == 0):
            print("Invalid option, please try again")
        else:
            selected_policy = int(selected_policy) - 1
            print("You have selected to use: " + available_policies[selected_policy])
            policy_to_update = available_policies[selected_policy]
            policy_selected =True
    
    # Get the policy id
    policy_instance = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
    try:
        policies = policy_instance.list_policies(api_version, overrides=overrides)
        for policy in policies.policies:
            if policy.name == policy_to_update:
                return(policy.id)
    except ApiException as e:
        print("An exception occurred when calling PoliciesApi.list_policies: %s\n" % e)

# This function gets the rule ID for any rules to be assigned
# It accepts the "rule_to_apply" which is the rule name
# and it accepts the rule_type; which can be one of "ips", "im" or "li"
# It will then search the rules for the rule_to_apply 
# and return the rule ID   
def getruleid(rule_type, rule_to_apply, configuration, api_version):
    # Get the rule id
    policy_instance = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
    if("ips" in rule_type):
        rule_instance = deepsecurity.IntrusionPreventionRulesApi(deepsecurity.ApiClient(configuration))
    if("im" in rule_type):
        rule_instance = deepsecurity.IntegrityMonitoringRulesApi(deepsecurity.ApiClient(configuration))
    if("li" in rule_type):
        rule_instance = deepsecurity.LogInspectionRulesApi(deepsecurity.ApiClient(configuration))
    rule_id = 0
    try:
        if("ips" in rule_type):
            rule_response = rule_instance.list_intrusion_prevention_rules(api_version)
            attrs = rule_response._intrusion_prevention_rules
            rule_id = getid(attrs, rule_to_apply)
        if("im" in rule_type):
            rule_response = rule_instance.list_integrity_monitoring_rules(api_version)
            attrs = rule_response._integrity_monitoring_rules
            rule_id = getid(attrs, rule_to_apply)
        if("li" in rule_type):
            rule_response = rule_instance.list_log_inspection_rules(api_version)
            attrs = rule_response._log_inspection_rules
            rule_id = getid(attrs, rule_to_apply)
        return(rule_id)
    except ApiException as e:
        print("An exception occurred when calling IntrusionPreventionRulesApi.list_intrusion_prevention_rules: %s\n" % e)

# This function is a continuation of the getruleid
# It is called to match the name and actually pull the "ID" field
# from the rule
def getid(attrs, rule_to_apply):
    ids = [len(attrs)]
    for x in attrs:
        if((getattr(x,"name") == rule_to_apply)):
            return(getattr(x,"id"))

# This function checks if a given rule is applied to the policy
# It simply returns:
#    True - the rule was already assigned to the policy
#    False - the rule is not assigned to the policy
def checkifruleassigned(rule_to_apply, rule_type, rule_id, policy_id, configuration, api_version, overrides):
    policy_instance = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
    try:
        found = False
        policies = policy_instance.list_policies(api_version, overrides=overrides)
        for policy in policies.policies:
            if policy.id == policy_id:
                if("ips" in rule_type):
                    if (rule_id != 0) and (policy.intrusion_prevention.rule_ids is not None):
                        for policy_ids in policy.intrusion_prevention.rule_ids:
                            if policy_ids == rule_id:
                                print(rule_type + " rule \"" + rule_to_apply + " is already assigned")
                                found = True
                                break
                if("im" in rule_type):
                    if (rule_id != 0) and (policy.integrity_monitoring.rule_ids is not None):
                        for policy_ids in policy.integrity_monitoring.rule_ids:
                            if policy_ids == rule_id:
                                print(rule_type + " rule \"" + rule_to_apply + " is already assigned")
                                found = True
                                break
                if("li" in rule_type):
                    if (rule_id != 0) and (policy.log_inspection.rule_ids is not None):
                        for policy_ids in policy.log_inspection.rule_ids:
                            if policy_ids == rule_id:
                                print(rule_type + " rule \"" + rule_to_apply + " is already assigned")
                                found = True
                                break
                if(found == False):
                    #id_array=arr.array('I',policy.intrusion_prevention.rule_ids)
                    print(rule_type + " rule \"" + rule_to_apply + " was not assigned, need to assign it to the policy")
        return(found)
    except ApiException as e:
        print("An exception occurred when calling PoliciesApi.list_policies: %s\n" % e)

# This function gets the last IM scan on a computer
# It returns the last IM scan time in epoch  
def getlastimscan(host_id, policy_id,configuration, api_version, overrides):
    try:
        computer_instance = deepsecurity.ComputersApi(deepsecurity.ApiClient(configuration))
        computers = computer_instance.list_computers(api_version, overrides=overrides)
        for computer in computers.computers:
            if(computer.policy_id == policy_id):
                if(computer.id == host_id):
                    return(computer.integrity_monitoring.last_integrity_scan)
    except ApiException as e:
        print("An exception occurred when calling ComputersApi.list_computers: %s\n" % e)

# This function gets the computer status
# It checks what is happening on a host in Cloud One or Deep Security
# and returns the current status of the computer
def getacstatus(host_id, policy_id,configuration, api_version, overrides):
    try:
        computer_instance = deepsecurity.ComputersApi(deepsecurity.ApiClient(configuration))
        computers = computer_instance.list_computers(api_version, overrides=overrides)
        for computer in computers.computers:
            if(computer.policy_id == policy_id):
                if(computer.id == host_id):
                    if(computer.tasks is not None):
                        print("Current status: " + computer.tasks.agent_tasks[0])
                        return(computer.tasks.agent_tasks[0])
                    else:
                        return(None)
    except ApiException as e:
        print("An exception occurred when calling ComputersApi.list_computers: %s\n" % e)

# This function is a debug function
# It's not used by any of the tests, but can be called if you're trying to debug
# It will print out current information on the status of a given computer
def getcomputerinfo(host_id, policy_id,configuration, api_version, overrides):
    try:
        computer_instance = deepsecurity.ComputersApi(deepsecurity.ApiClient(configuration))
        computers = computer_instance.list_computers(api_version, overrides=overrides)
        for computer in computers.computers:
            if(computer.policy_id == policy_id):
                if(computer.id == host_id):
                    print(computer)
    except ApiException as e:
        print("An exception occurred when calling ComputersApi.list_computers: %s\n" % e)

# This function lists the policies in the Cloud One or Deep Security Manager   
def listpolicies(configuration, api_version, overrides):
    try:
        # Get the policies
        policy_names = []
        policy_instance = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
        policy_response = policy_instance.list_policies(api_version, overrides=overrides)
        for policy in policy_response.policies:
            policy_names.append(policy.name)
        return(policy_names)
    except ApiException as e:
        print("An exception occurred when calling ComputersApi.list_computers: %s\n" % e)

# This function checks what computers the selected policy is assigned to
# It then prompts the user to confirm or select the right computer
# Once the computer has been selected it does a look up for the host ID
# It then returns the host ID
def gethostid(policy_id, configuration, api_version, overrides):
    try:
        # Get the hosts that are using the selected policy
        hosts_using_policy = []
        computer_instance = deepsecurity.ComputersApi(deepsecurity.ApiClient(configuration))
        computers = computer_instance.list_computers(api_version, overrides=overrides)
        for computer in computers.computers:
            computer_info = []
            if(computer.policy_id == policy_id):
                host_string = computer.display_name + "(" + computer.host_name + ")"
                hosts_using_policy.append(host_string)
        
        # If not hosts are using the selected policy, exit
        if hosts_using_policy is None:
            print("There are no hosts with the selected policy assigned.  Please assign the policy to the host under test and re-run the script")
            exit()
        
        # Otherwise prompt the user to confirm
        if (len(hosts_using_policy) == 1):
            y_or_n_selected = False
            
            while(y_or_n_selected ==False):
                print("The host under test is: " + hosts_using_policy[0])
                print("Is this correct (y/n)?")
                host_correct = input()
                if(host_correct.isalpha() and len(host_correct) == 1):
                    if("y" in host_correct.lower()):
                        print("Using host: " + hosts_using_policy[0])
                        y_or_n_selected = True
                    else:
                        print("Please assign the policy you selected to the host under test or select the policy assigned to the host under test and try again")
                        exit() 
                else:
                    print("Invalid entry, please try again")
        
        # If there is more than one host using the policy
        # Prompt the user to provide the system under test
        if (len(hosts_using_policy) > 1):
            count = 1
            for host in hosts_using_policy:
                print(str(count) + " = " + host)
                count+=1
            print("Enter the number for the host you will be running these tests on?")
            selected_host = input()
            if (not selected_host.isdigit()) or (int(selected_host) > (len(hosts_using_policy) + 1) or selected_host == 0):
                    print("Invalid option, please try again")
                    selected_host = 0
            selected_host = int(selected_host) - 1
            print("You have selected to use: " + hosts_using_policy[selected_host]  + " as the host under test")
            host_to_select = hosts_using_policy[selected_host]
        else:
            print("This policy is assigned to: " + hosts_using_policy[0] + " so this host is selected as the host under test")
            host_to_select = hosts_using_policy[0]
            
        # Get the host id
        for computer in computers.computers:
            if(computer.host_name in host_to_select):
                return(computer.id)
                
    except ApiException as e:
        print("An exception occurred when calling ComputersApi.list_computers: %s\n" % e)

# This function will run a given command
# It returns the output of that command
def runcommand(cmd):
    print("Running command: " + cmd)
    process_info = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    output = process_info.stdout.read()
    return(output)

# This function will call dsa_control to send a heartbeat
# It is used to get the events back to Cloud One or Deep Security Manager
def sendheartbeat(operating_system):
    if("ubuntu" in operating_system or "redhat" in operating_system):
        cmd = "sudo /opt/ds_agent/dsa_control -m"
        output = runcommand(cmd)
    if("windows" in operating_system):
        cmd = "\"C:\Program Files\Trend Micro\Deep Security Agent\dsa_control\" -m"
        output = runcommand(cmd)
    