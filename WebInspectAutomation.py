import requests
import json
import os
import sys
import time

class WebInspectAutomation:
  
    
    #initialize instance attributes
    def __init__(self):
        self.base_url,self.default_file_path,self.SSCUrl,self.SSCAuthToken,self.ApplicationVersionID = self.argument_validation()
        self.WIScansUrl = self.base_url + "/Scanner/Scans/"
        self.headers = {
            'Content-Type': "application/json",
            'cache-control': "no-cache",
            }

    #Display error and stop program execution
    def display_error(self,message):
        print("Error: {}".format(message), flush=True)
        sys.exit(1)

    #Capture command line arguments
    ###########################
    ##  Collect Scan Args   ###
    ###########################
    def argument_validation(self):
        print ("############ Scan Parameters ############", flush=True)
        with open('arguments.json') as json_file:
            data = json.load(json_file)
            #Grab the BaseUrl  from the command line arguments
            if data['BaseUrl']:
                base_url = data['BaseUrl']
                print("Base WI URL: " + base_url, flush=True)
            else:
                self.display_error('BaseUrl not defined in arguments.json')
            #Grab the Payload file location from the command line arguments
            if data['DefaultFilePath']:
                default_file_path = data['DefaultFilePath']
                print ("Default path for PayloadFile.txt and results: " + default_file_path, flush=True)
            else:
                default_file_path = './'
                print("Default path for PayloadFile.txt and results is current directory",flush = True)   
            #Grab the SSC URL
            if data['SSCUrl']:
                SSCUrl = data['SSCUrl']
                print ("SSC URL: " + SSCUrl, flush=True)
            else:
                self.display_error('SSC URL not defined in arguments.json')

            #Grab the SSC Auth token
            if data['SSCAuthToken']:
                SSCAuthToken = data['SSCAuthToken']
                print ("SSC Auth Token: " + SSCAuthToken, flush=True)
            else:
                self.display_error('SSC Auth Token not defined in arguments.json')
            #Grab the Application Version ID
            if  data['ApplicationVersionID']:
                ApplicationVersionID =  data['ApplicationVersionID']
                print ("App Version ID in SSC: " + ApplicationVersionID, flush=True)
            else:
                self.display_error("App version ID not defined in arguments.json")
            print ("#########################################", flush=True)
            return base_url,default_file_path,SSCUrl,SSCAuthToken,ApplicationVersionID


     
        

    def get_scans_by_status(self,status):
        querystring = {"Status": status}
        status_response = requests.request("Get", self.WIScansUrl, params=querystring, headers=self.headers)
        if(status_response.status_code != 200):
            print("Exiting: GET Scan by status response is {}".format(status_response.status_code))
            sys.exit(1)
        json_data = json.loads(status_response.text)
        return len(json_data)
        

    def start_scan(self):
        filepath = "{}\PayloadFile.txt".format(self.default_file_path)
        print("Looking for {}".format(filepath))
        f = open(self.default_file_path + "\PayloadFile.txt", "r")
        payload = f.read()
        f.close()
        print("File was found")
        #Make the request to the API
        response = requests.request("POST", self.WIScansUrl, data=payload, headers=self.headers)
        if(response.status_code != 200):
            print("Exiting: New Scan Failed, status response is {}".format(response.status_code))
            sys.exit(1)
       
        #Convert response to Dictionary 
        json_data = json.loads(response.text)
        return json_data.get("ScanId")
        

    def wait_for_status_change(self,scan_Id):
        ###########################
        ##      Scan Status     ###
        ###########################

        #Build the URL for getting scan status
        ScanStatusUrl = self.WIScansUrl + scan_Id

        #Wait for the scan to complete before exporting results
        querystring = {"action":"WaitForStatusChange"}
        response = requests.request("Get", ScanStatusUrl, params=querystring, headers=self.headers)
        if(response.status_code != 200):
            print("Exiting: Wait for status change Failed, status response is {}".format(response.status_code))
            sys.exit(1)

    def print_vulnerabilities(self,scan_Id):

        ###########################
        ##      Print Vulns     ###
        ###########################

         #create the URL for requesting issue from sessionchecks
        VulnsUrl = "{}{}/data/SessionChecks".format(self.WIScansUrl,scan_Id)
        response = requests.request("Get", VulnsUrl, headers=self.headers)
        if(response.status_code != 200):
            print("Exiting: Get vulnerabilities Failed, status response is {}".format(response.status_code))
            sys.exit(1)
        json_data = json.loads(response.text)
        #Make the vulnerability output pretty
        jsondump = json.dumps(json_data, indent = 4, sort_keys=True)
        print(jsondump, flush=True)
        if not os.path.exists(self.default_file_path + "\\" + scan_Id):
        #Create a folder for this scan id
            os.mkdir(self.default_file_path + "\\" + scan_Id)
        outputFile = open(self.default_file_path + "\\" + scan_Id +"\\Vulnerabilities.txt","w")
        outputFile.write(jsondump)
        outputFile.close()

    def download_fpr(self,scan_Id):
        ###########################
        ##      Download FPR    ###
        ###########################
        fprUrl ="{}{}.fpr".format(self.WIScansUrl,scan_Id)
        response = requests.get(fprUrl)
        if(response.status_code != 200):
            print("Exiting: Download FPR, status response is {}".format(response.status_code))
            sys.exit(1)
        with open(self.default_file_path + "\\" + scan_Id + "\\" + "Vulnerabilities.fpr", 'wb') as f:  
            f.write(response.content)
        f.close()

    def download_scan(self,scan_Id):
        ###########################
        ##     Download Scan    ###
        ###########################
        scanUrl ="{}{}.scan".format(self.WIScansUrl,scan_Id)
        r = requests.get(scanUrl)
        if(r.status_code != 200):
            print("Exiting: Download FPR, status response is {}".format(r.status_code))
            sys.exit(1)
        with open(self.default_file_path + "\\" + scan_Id + "\\" + "Vulnerabilities.scan", 'wb') as f:  
            f.write(r.content)
        f.close()

    def upload_to_SSC(self,scan_Id):
        ###########################
        ##  Upload FPR to SSC   ###
        ###########################
        os.system("fortifyclient -url " + self.SSCUrl + " -authtoken " + self.SSCAuthToken + " uploadFPR " + "-f \"" + self.default_file_path  + "\\" + scan_Id + "\\" + "Vulnerabilities.fpr\"" + " -applicationVersionID " + self.ApplicationVersionID)


if __name__ == "__main__":
    WIA = WebInspectAutomation()


    running_scans = WIA.get_scans_by_status("Running")
   
    #Pause if there are any running scans
    while (running_scans > 0):

        print ("{} Scans running.  Pausing for 60 seconds".format(running_scans), flush=True)
        time.sleep(60)
        #Check for running scans
        running_scans = WIA.get_scans_by_status("Running")
    print("No scans running, proceeding to start a new scan",flush=True)    
    scan_Id = WIA.start_scan()
    #Print and store the ScanId of running scan from response payload
    print("ScanId {} is now running".format(scan_Id), flush=True)
    WIA.wait_for_status_change(scan_Id)
    WIA.print_vulnerabilities(scan_Id)
    WIA.download_fpr(scan_Id)
    WIA.download_scan(scan_Id)
    WIA.upload_to_SSC(scan_Id)