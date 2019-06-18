# WebInspect Automation
Sample Python script for automating dynamic scanning with WebInspect and pushing results to SSC
1. Checks for running scans and queues if an existing scan is running
2. Takes payload.txt file from DefaultFilePath to start scan.  The payload.txt file is a JSON definition that defines the scan
3. Starts scan saving scan ID for generating results
4. Watches for scan to complete
5. Pulls scan as txt, .scan, and .fpr
6. Uploads FPR to SSC

## Requirements
1. WebInspect 18.2+
2. Python 3.7
3. SSC 18.2+
4. Fortifyclient utility 18.2+

## Sample Command
WebInspectAutomation.py BaseUrl http://WebInspectMachine:8083/webinspect/ DefaultFilePath "C:\DefaultFilePath" SSCUrl http://SSCServer:8080/ssc SSCAuthToken AuthTokenFromSSC ApplicationVersionID SSCAppVersionID ScanMode Payload

## To Do
1. Port to Java
2. Incremental Scanning support
3. URL scan mode
4. Scan settings mode