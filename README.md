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

### Scanning Features
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| -pml | bool | false | Enable predictive machine learning detection |
| -feedback | bool | false | Enable Smart Protection Network feedback |

### Performance Optimization
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| -maxFileSize | int64 | 500MB | Maximum file size to scan (in bytes) |
| -minFileSize | int64 | 1KB | Minimum file size to scan (in bytes) |
| -maxMemoryMB | int64 | 1024 | Maximum memory usage in MB |
| -iothrottle | int | 0 | Milliseconds to wait between file operations |

### File Filtering
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| -skipExt | string | ".iso,.vmdk,.vdi,.dll" | Comma-separated list of extensions to skip |
| -skipMimeTypes | string | "application/x-executable,application/x-sharedlib" | Comma-separated list of MIME types to skip |

### Advanced Options
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| -internal_address | string | "" | Internal Service Gateway Address |
| -internal_tls | bool | true | Use TLS for internal Service Gateway |

*Note: Parameters marked with an asterisk (*) are required*

## Example Usage

### Basic Usage
```sh
./v1_fs_go_scanner -apiKey=<v1_api_key> -directory=/tmp/some_folder -maxWorkers=200 -tags=dev,us-east-1,temp_project -verbose=true
```

### Optimized for Large Volumes
```sh
./v1_fs_go_scanner \
  -apiKey=<v1_api_key> \
  -directory=/data \
  -maxWorkers=150 \
  -maxMemoryMB=4096 \
  -maxFileSize=250000000 \
  -minFileSize=4096 \
  -skipExt=".iso,.vmdk,.vdi,.dll,.exe,.bak,.tmp" \
  -iothrottle=10 \
  -verbose=true \
  -tags=dev,us-east-1,temp_project \
  -exclude-dir exclusion_dir_list.txt
```

## Output Files

The program creates the following log files in its running directory:

| Filename | Description |
|----------|-------------|
| "{timestamp}-Scan.log" | Documents total files scanned, scan results, and execution time |
| "{timestamp}-error.log" | Logs any file scan errors |
| "{timestamp}-skipped_files.log" | Logs files that were skipped due to errors or filters |
| "scan_checkpoint.json" | Periodic checkpoint file for scan progress (enables resume capability) |

## Performance Features

- **Progress Monitoring**: Shows real-time scanning progress every 5 seconds
- **Memory Management**: Automatically pauses scanning when memory usage is high
- **I/O Control**: Throttling option to prevent system overload
- **Checkpointing**: Enables resuming interrupted scans
- **Smart Filtering**: Skip files based on size, type, and extension
- **Concurrent Processing**: Optimized worker pool for parallel scanning

## Best Practices

1. For large volumes (>1TB):
   - Use appropriate `-maxWorkers` based on CPU cores
   - Set `-maxMemoryMB` to prevent memory exhaustion
   - Enable `-iothrottle` to prevent I/O overload
   - Use `-skipExt` and `-skipMimeTypes` to filter unnecessary files

2. For network-mounted volumes:
   - Reduce `-maxWorkers` to prevent network saturation
   - Increase `-iothrottle` value
   - Consider using smaller `-maxFileSize` limit

3. For local SSDs:
   - Can use higher `-maxWorkers` values
   - Minimal or no `-iothrottle` needed
   - Can handle larger `-maxFileSize` values

## Error Handling

The scanner implements several error handling mechanisms:
- Automatic retry for failed scans
- Timeout handling for stuck operations
- Graceful shutdown on interruption
- Detailed error logging
- Skip logging for filtered files
