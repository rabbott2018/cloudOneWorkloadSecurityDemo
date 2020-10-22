from cloud_one_workload_security_demo_utils import runcommand, getcomputerinfo, getacstatus, sendheartbeat
import time

# This is the Docker AM test
# This test checks if Docker is installed
# If it's not it will install Docker
# Then it will attempt to download and instantiate a Docker container that contains malware
# Once complete if Docker was previously not installed it will remove it
# The test will also perform a heartbeat to ensure the events get back to 
# Cloud One Workload Security or Deep Security Manager
def dockeramtest(host_id, policy_id, configuration, api_version, overrides, operating_system):
    # Check if Docker is installed
    print("---Running The Docker Test---")
    docker_installed = False
    if("ubuntu" in operating_system or "redhat" in operating_system):
        print("Checking if Docker is installed")
        cmd = "sudo docker version" 
        output = runcommand(cmd)
        if(output == ""):
            print("Docker not found; installing Docker")
            if("ubuntu" in operating_system):
                cmd = "sudo apt-get install docker.io -y" 
                output = runcommand(cmd)
            if("redhat" in operating_system):
                cmd = "sudo yum install docker" 
                output = runcommand(cmd)
        else:
            docker_installed = True
    
    if("windows" in operating_system):
        print("This test only works on ubuntu and redhat currently.  Exiting!!")
        return()
        cmd = "docker version" 
        output = runcommand(cmd)
        if("docker" in output.lower() and "version" in output.lower() and "build" in output.lower()):
            print("Found docker installed already")
            docker_installed = True
        else:
            cmd = "curl https://download.docker.com/win/stable/Docker%20Desktop%20Installer.exe -o Docker_Desktop_Installer.exe" 
            output = runcommand(cmd)
            cmd = "Docker_Desktop_Installer.exe install --quiet" 
            output = runcommand(cmd)
    
    # Run the tests     
    runtest(host_id, policy_id, configuration, api_version, overrides, operating_system)        
    
    #Clean up after the tests and reset the system to it's original state
    if(docker_installed == False):
        cleanup(operating_system)
        
    # Perform a heartbeat to get the events to Cloud One or Deep Security Manager
    sendheartbeat(operating_system)

# This function will run the test
# It will attempt to download and instantiate a Docker container with malware
# The test will then trigger a manual scan for malware
# Note this test only works on Ubuntu and Redhat
def runtest(host_id, policy_id, configuration, api_version, overrides, operating_system):
    #Attempt to download and instantiate a container with malware
    if("ubuntu" in operating_system or "redhat" in operating_system):
        cmd = "sudo docker pull philippbehmer/docker-eicar:latest" 
        output = runcommand(cmd) 
        cmd = "sudo docker run philippbehmer/docker-eicar:latest" 
        output = runcommand(cmd)
        cmd = "sudo /opt/ds_agent/dsa_control -m \"AntiMalwareManualScan:true\""
        output = runcommand(cmd)
        time.sleep(10)
        checkstatus(host_id, policy_id, configuration, api_version, overrides)

# This function will clean up the system by removing Docker if it wasn't previously instlled
def cleanup(operating_system):
    print("Uninstalling Docker")
    if("ubuntu" in operating_system):
        cmd = "sudo apt-get --purge remove docker.io -y" 
        output = runcommand(cmd) 
    if("redhat" in operating_system):
        cmd = "sudo yum remove docker" 
        output = runcommand(cmd)
    if("windows" in operating_system):
        cmd = "Docker_Desktop_Installer.exe uninstall --quiet" 
        output = runcommand(cmd)
        
# In this test we do a manual scan for malware
# This function will check the status of the host to ensure the malware scan is complete
def checkstatus(host_id, policy_id,configuration, api_version, overrides):
    done = False
    while done == False:
        print("Checking the computer status...")
        status = getacstatus(host_id, policy_id, configuration, api_version, overrides)
        if(status is not None):
            time.sleep(10)
        else:
            print("Done")
            done = True