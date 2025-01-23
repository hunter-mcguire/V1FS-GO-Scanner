# Vision One File Security Go Scanner

### Overview
The Vision One File Security Go Scanner is a command-line program written in Go. It allows users to recursively scan directories for potential security issues using the Vision One API. The scanner now supports both command-line arguments and a YAML configuration file for parameter management.

### Link to the SDK
[Trend Micro Vision One File Security Go SDK](https://github.com/trendmicro/tm-v1-fs-golang-sdk)

---

## Parameters
You can configure the scanner via command-line arguments or a YAML configuration file. Command-line arguments will override the values in the YAML configuration file.

| Parameter        | Type                        | Description                                                                                           |
|------------------|-----------------------------|-------------------------------------------------------------------------------------------------------|
| **-apiKey**      | *string*                   | Vision One API Key / V1_FS_KEY environment variable *(required)*                                      |
| **-config**      | *string*                   | Path to the YAML configuration file. Default: `config.yaml`                                          |
| **-directory**   | *string*                   | Path to the directory to scan recursively *(required if not in YAML)*                                |
| **-maxWorkers**  | *int*                      | Maximum number of concurrent file scans. Default: `100`. Unlimited: `-1`                             |
| **-region**      | *string*                   | Vision One Region. Default: `"us-east-1"`                                                            |
| **-tags**        | *string (comma-separated)* | Up to 8 strings separated by commas. Default: `""`                                                   |
| **-pml**         | *bool*                     | Enable predictive machine learning detection. Default: `false`                                       |
| **-feedback**    | *bool*                     | Enable Smart Protection Network feedback. Default: `false`                                           |
| **-verbose**     | *bool*                     | Logs all scans to stdout. Default: `false`                                                           |
| **-exclude-dir** | *string*                   | Path to a file containing directories to exclude from scanning.                                       |
| **-timeoutlimit**| *int*                      | Timeout limit in seconds for scanning each file. Default: `10`                                       |

**Note:** Parameters marked with `*` are required either in the YAML file or as command-line arguments.  
Allowed boolean values: `true | false`

---

## YAML Configuration
The scanner can be configured using a `config.yaml` file, making it easier to manage complex parameter sets. Below is an example configuration:

```yaml
region: "us-east-1"
directory: "/tmp/some_folder"
verbose: true
pml: false
feedback: false
maxWorkers: 200
internalAddress: ""
internalTLS: true
excludeDir: "exclusion_dir_list.txt"
timeoutLimit: 100
tags:
  - dev
  - us-east-1
  - temp_project
```

---

## Example Usage

### Using Command-Line Arguments:
```sh
./v1_fs_go_scanner -apiKey=<v1_api_key> -directory=/tmp/some_folder --timeoutlimit=100 -maxWorkers=200 -tags=dev,us-east-1,temp_project -verbose=true -exclude-dir exclusion_dir_list.txt
```

### Using YAML Configuration:
```sh
./v1_fs_go_scanner -apiKey=<v1_api_key> -config=config.yaml
```

### Mixing YAML and Command-Line:
Command-line arguments override YAML configurations:
```sh
./v1_fs_go_scanner -apiKey=<v1_api_key> -config=config.yaml -verbose=false -timeoutlimit=50
```

---

## Output Files
The scanner will generate the following log files in the working directory:

| FileName                         | Description                                                                                       |
|----------------------------------|---------------------------------------------------------------------------------------------------|
| `{timestamp}-Scan.log`           | Logs details of the scan, including total files scanned, time taken, and results.                 |
| `{timestamp}-error.log`          | Logs any errors encountered during file scanning.                                                |
| `{timestamp}-skipped_files.log`  | Logs files skipped due to errors or exceeding the timeout limit, along with error details.        |

---

