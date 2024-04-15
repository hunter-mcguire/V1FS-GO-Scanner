# V1FS-GO-Scanner
### The scanner is a Golang binary, which is used as a command line program. Below are the following paramaters allowed for usage in the program.
<br>
<br>

| Paramater| Type | Description |
| ----------- | ----------- | ----------- |
-apiKey | *string* | Vision One API Key / V1_FS_KEY environment variable *
-directory | *string* | Path to Directory to scan recursively * 
-maxWorkers | *int* | Max number concurrent file scans. Default: 100,  Unlimited: -1
-region | *string* | Vision One Region. Default: "us-east-1" 
-tags | *string(comma-seperated)* | Up to 8 strings separated by commas
-verbose | *bool* | "true" Logs all scans to stdout

*Note the required paramaters are marked with an asterisk* *
<br>
<br>

### Example Usage: <br><br>
```sh
./v1_fs_go_scanner -apiKey=<v1_api_key> -directory=/tmp/some_folder -maxWorkers=200 -tags=dev,us-east-1,temp_project -verbose=true
```
<br>
<br>

Additionally, this program will create to two files in the directory from which it is ran.
| FileName | Description |
| ----------- | ----------- |
"{start-timstamp}-Scan.log" | Documents the total num files scan and time to run.
"{start-timstamp}-error.log" | Logs any file scan errors