# WebInspect Automation
Sample WebInspect script for automating dynamic scanning and pushing results to SSC
1. Checks for running scans and queues if an existing scan is running
2. Takes payload.txt file from DefaultFilePath to start scan.  The payload.txt file is a JSON definition that defines the scan
3. Starts scan saving scan ID for generating results
4. Watches for scan to complete
5. Pulls scan as txt, .scan, and .fpr
6. Uploads FPR to SSC

## Requirements
-WebInspect 18.2+
-Python 3.7
-SSC 18.2+
-Fortify update utility 18.2+

## Sample Command
WebInspectAutomation.py BaseUrl http://WebInspectMachine:8083/webinspect/ DefaultFilePath "C:\DefaultFilePath" SSCUrl http://SSCServer:8080/ssc SSCAuthToken AuthTokenFromSSC ApplicationVersionID SSCAppVersionID ScanMode Payload
