# Vision One File Security Go Scanner

The scanner is a Go binary designed to function as a command-line program. It recursively scans all items in a given directory path with advanced optimization features for large-scale scanning operations.

## SDK Reference
Link to Github SDK Repo: https://github.com/trendmicro/tm-v1-fs-golang-sdk

## Parameters

### Required Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| -apiKey | string | Vision One API Key (can also use V1_FS_KEY environment variable) |
| -directory | string | Path to directory to scan recursively |

### Basic Configuration
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| -maxWorkers | int | 100 | Max number of concurrent file scans (use -1 for unlimited) |
| -region | string | "us-east-1" | Vision One Region |
| -tags | string | "" | Up to 8 comma-separated strings |
| -verbose | bool | false | Log all scans to stdout |
| -exclude-dir | string | "" | Path to file containing directories to exclude |

### Performance Optimization
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| -maxFileSize | int64 | 500MB | Maximum file size to scan (in bytes) |
| -minFileSize | int64 | 1KB | Minimum file size to scan (in bytes) |
| -maxMemoryMB | int64 | 1024 | Maximum memory usage in MB |
| -iothrottle | int | 0 | Milliseconds to wait between file operations |

### Feature Flags
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| -pml | bool | false | Enable predictive machine learning detection |
| -feedback | bool | false | Enable Smart Protection Network feedback |

## Output Files

The program creates the following log files in its running directory:

| Filename | Description |
|----------|-------------|
| "{timestamp}-Scan.log" | Documents total files scanned, scan results, and execution time |
| "{timestamp}-error.log" | Logs any file scan errors |

## Performance Tips

### Exclusion File
Create a text file with directories to exclude (one per line). For optimal performance, consider excluding system directories that don't need scanning:

Recommended exclusions for Linux systems:
```
/sys
/proc
/dev
/run
/etc/ssl
/var/lib/docker
/var/run
/boot
```

Example usage with exclusions:
```sh
# Create exclusions.txt with your preferred directories to exclude
./v1_fs_scanner_linux \
  -apiKey=$TMAS_API_KEY \
  -directory=/path/to/scan \
  -exclude-dir=exclusions.txt \
  -maxWorkers=250 \
  -maxMemoryMB=4096
```

### Best Practices for Large Volumes

1. For volumes > 1TB:
   - Use appropriate `-maxWorkers` based on CPU cores (try 200-300)
   - Set `-maxMemoryMB` to prevent memory exhaustion (4096 or higher)
   - Use `-iothrottle=1` to prevent I/O overload
   - Create an exclusions file to skip unnecessary directories

2. For network-mounted volumes:
   - Reduce `-maxWorkers` to prevent network saturation
   - Increase `-iothrottle` value (try 5-10ms)
   - Consider using smaller `-maxFileSize` limit

3. For local SSDs:
   - Can use higher `-maxWorkers` values
   - Minimal or no `-iothrottle` needed
   - Can handle larger `-maxFileSize` values

## Example Configurations

### Basic Usage
```sh
./v1_fs_scanner_linux -apiKey=<v1_api_key> -directory=/tmp/some_folder
```

### Optimized for Large Volumes
```sh
./v1_fs_scanner_linux \
  -apiKey=$TMAS_API_KEY \
  -directory=/data \
  -maxWorkers=250 \
  -maxMemoryMB=4096 \
  -maxFileSize=50000000 \
  -minFileSize=1000 \
  -skipExt=".iso,.vmdk,.vdi,.dll,.exe,.bak,.tmp" \
  -iothrottle=1 \
  -verbose=true \
  -tags=dev,us-east-1,temp_project \
  -exclude-dir=exclusions.txt
```
