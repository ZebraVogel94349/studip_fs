# studip_fs

FUSE-filesystem that mounts Stud.IP files. This program logs into Stud.IP, retrieves the list of courses
and provides access to their files/folders as a filesystem, using the JSON API. It was tested and developed for use with
the Stud.IP of Leibniz Universität Hannover, but may also work with the Stud.IP of other Universities. Let me know, if
you have tested it. 

Currently, only a read-only access is implemented. The program only starts downloading the list of directory contents
when opening the directory and only starts downloading files when opening them to reduce API requests and bandwidth. 
Files are downloaded and cached in chunks of variable size, to further reduce bandwidth.

Note, that this a very early version of this program and there may be bugs. Please inform me, if you find any.
The program outputs its logs to /tmp/studdebug_out.txt. 

## Requirements

- Linux with FUSE3/libfuse3
- C++ compiler
- libcurl
- nlohmann-json
- cmake

## Build

```bash
mkdir -p build
cmake -S . -B build
cmake --build build
```

## Configuration

The program has to be configured using a config file. If no config file exists, the program
creates one. Config files are searched for and created in the following paths in that order:

1. `$STUDIP_FS_CONFIG`
2. `$XDG_CONFIG_HOME/studip_fs/config.json`
3. `$HOME/.config/studip_fs/config.json`
4. local `studip_fs.json`

Explanation of configuration options:
- username: your WebSSO username
- password: your WebSSO password
- page_limit: Amount of files/folders loaded per API request. Since the program always loads the complete list of contents of a directory, changing this to a low number causes more API requests. Keep this number high as long as it doesn't cause any issues.
- tree_cache: time in seconds, how long the list of directory contents gets cached
- request_delay: delay between all API requests in milliseconds
- request_timeout: timeout for API requests in seconds
- chunk_size_fraction: files are downloaded and cached in chunks of chunk_size_fraction * file_size bytes
- min_chunk_size: minimum size of cache chunks in bytes, even if chunk_size_fraction * file_size is smaller 
- max_chunk_size: masximum size of cache chunks in bytes, even if chunk_size_fraction * file_size is bigger
- cookie_file_path: libcurl uses this file to store the session cookies
- mount_point: path where the filesystem should be mounted
- the url options are there to configure the program to work with a different Stud.IP instance. 
Note: For the path options, only absolute and local paths are supported (so no "~" or environment variables)

## Running the program

To run studip_fs, run the studip_fs binary in the build directory. The file can be moved
to any location you want, it should run from everywhere. Make sure that your WebSSO username
and password and the mount point are configured in your config file, that the directory for
the mount point exists and that you have writing permissions there.

## Unmount:

To unmount the filesystem, run
```bash
fusermount -u your_mount_point
```
or, if you want to force-unmount it, while it's used, run
```bash
fusermount -zu your_mount_point
```

