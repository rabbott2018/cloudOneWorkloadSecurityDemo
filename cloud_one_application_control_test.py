import deepsecurity
from deepsecurity.rest import ApiException
from pprint import pprint
import subprocess
from subprocess import Popen, PIPE, STDOUT
from cloud_one_workload_security_demo_utils import runcommand, getacstatus, sendheartbeat
import time

# This is the application control test
# This test will check if Application Control is turned on
# If it is not on, it will turn it on
# The test will then attempt to download and run docker on the system
# This should trigger an event
# After the test, docker will be deleted/removed
# If Application control was not on previously, it will be turned off again
# The test will also perform a heartbeat to ensure the events get back to 
# Cloud One Workload Security or Deep Security Manager
def applicationcontroltest(host_id, policy_id, configuration, api_version, overrides, operating_system):
    print("---Running The Application Control Test---")
    #Check if Application control is already enabled
    enabled = False
    policies_api = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
    application_control_policy_extension = deepsecurity.ApplicationControlPolicyExtension()
    if(application_control_policy_extension.state is not None):
       if("on" in application_control_policy_extension.state):
           enabled = True
        
    #If application control is not enabled, enable it
    if(enabled == False):
        print("Enabling Application Control")
        enabledisableapplicationcontrol(policy_id, policies_api, application_control_policy_extension, api_version, "on")
        done = False
        while done == False:
            print("Waiting for Application Control Baseline to finish...")
            #put a sleep here to allow the policy to update and the baseline to start
            time.sleep(30)
            status = getacstatus(host_id, policy_id, configuration, api_version, overrides)
            if(status is not None):
                if("sending policy" in status.lower() or "application control inventory scan in progress" in status.lower() or "security update in progress" in status.lower()):
                    time.sleep(10)
            else:
                print("Application Control Baseline complete")
                done = True
        
    #Run the tests
    runtest(operating_system)
    
    # If Application Control was not previously on, turn it off again to return the policy to it's original state
    if(enabled == False):
        enabledisableapplicationcontrol(policy_id, policies_api, application_control_policy_extension, api_version, "off")
        
    #Clean up after the tests and reset the system to it's original state
    cleanup(policy_id, policies_api, application_control_policy_extension, api_version, enabled, operating_system)
    
    # Perform a heartbeat to get the events to Cloud One or Deep Security Manager
    sendheartbeat(operating_system)
    print("---Application Control Test Completed---")

# This function will turn Application Control on or off
# If state is "on" then it will turn Application Control on
# If the state is "off" then it will turn Application Control off
def enabledisableapplicationcontrol(policy_id, policies_api, application_control_policy_extension, api_version, state):
    # Set the Application Control state
    print("Setting the Application Control state to: " + state)
    application_control_policy_extension.state = state
    application_control_policy_extension.block_unrecognized = "true"
    policy = deepsecurity.Policy()
    policy.application_control = application_control_policy_extension
         
    # Modify the policy on Deep Security Manager
    modified_policy = policies_api.modify_policy(policy_id, policy, api_version)
    #pprint(modified_policy)      

# This test will run the tests
# It attempts to download docker and then run it
def runtest(operating_system):
    if("ubuntu" in operating_system):
        # Attempt to install docker
        cmd = "sudo apt install docker &" 
        output = runcommand(cmd)
    if("redhat" in operating_system):
        # Attempt to install docker
        cmd = "sudo yum install docker -y &" 
        output = runcommand(cmd)
        cmd = "sudo docker --version" 
        output = runcommand(cmd)
    if("windows" in operating_system):
        cmd = "curl https://download.docker.com/win/stable/Docker%20Desktop%20Installer.exe -o dockerinstaller.exe" 
        output = runcommand(cmd)
        cmd = "dockerinstaller.exe" 
        output = runcommand(cmd) 

#This function will clean up the system by removing any remnants of Docker left by the test
def cleanup(policy_id, policies_api, application_control_policy_extension, api_version, enabled, operating_system):
    if("ubuntu" in operating_system):
        # Remove docker
        cmd = "sudo apt-get --purge remove docker -y &"
        output = runcommand(cmd)
        # Not sure why I have to do this twice
        cmd = "sudo apt-get --purge remove docker -y &"
        output = runcommand(cmd)
    if("redhat" in operating_system):   
        # Remove docker
        cmd = "sudo yum remove docker -y &"
        output = runcommand(cmd)
    if("windows" in operating_system):
        cmd = "del dockerinstaller.exe" 
        output = runcommand(cmd)