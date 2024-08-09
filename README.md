# Vision One File Security Go Scanner
### The scanner is a Go binary designed to function as a command-line program. It takes a directory file path as input to perform a recursive scan of all items in the root directory. The program accepts the following parameters:
<br>
Link to Github SDK Repo: https://github.com/trendmicro/tm-v1-fs-golang-sdk
<br>
<br>

| Paramater| Type | Description |
| ----------- | ----------- | ----------- |
-apiKey | *string* | Vision One API Key / V1_FS_KEY environment variable *
-directory | *string* | Path to Directory to scan recursively * 
-maxWorkers | *int* | Max number concurrent file scans. Default: 100,  Unlimited: -1
-region | *string* | Vision One Region. Default: "us-east-1" 
-tags | *string(comma-seperated)* | Up to 8 strings separated by commas. Default: ""
-pml | *bool* | Enable predictive machine learning detection. Default: false
-feedback | *bool* | Enable Smart Protection Network feedback. Default: false
-internal_address | *string* | Internal Service Gateway Address. ex. 192.168.2.5:443
-internal_tls | *bool* | Use TLS for internal Service Gateway
-verbose | *bool* | Logs all scans to stdout. Default: false

<br>
*Note the required paramaters are marked with an asterisk
<br>
<br>
*Allowed bool values: true | false*
<br>
<br>

### Example Usage: <br><br>
Usage to cloud based scanner

```sh
./v1_fs_go_scanner -apiKey=<v1_api_key> -directory=/tmp/some_folder -maxWorkers=200 -tags=dev,us-east-1,temp_project -verbose=true
```
<br>

Usage to Service Gateway scanner

```sh
./v1_fs_go_scanner -apiKey=<v1_api_key> -directory=/tmp/some_folder -maxWorkers=200 -tags=dev,us-east-1,temp_project -verbose=true -internal_address=192.168.2.5:443
```
<br>

Additionally, this program will create to two files in the directory from which it is ran.
| FileName | Description |
| ----------- | ----------- |
"{start-timstamp}-Scan.log" | Documents the total num files scan and time to run.
"{start-timstamp}-error.log" | Logs any file scan errors
