# psjson - Process Information in JSON Format

`psjson` is a lightweight C program that displays information about running processes on Linux systems in JSON format, similar to what the `ps` command provides but with structured output.

## Features

- Shows all running processes with detailed information
- Outputs in clean, parseable JSON format
- Includes the full executable path for each process
- Lightweight and fast

## Requirements

- Linux operating system
- GCC compiler
- Standard C libraries

## Compilation

To compile the program, run:

```bash
gcc -o psjson psjson.c
```

## Usage

Simply run the executable:

```bash
./psjson
```

To save the output to a file:

```bash
./psjson > processes.json
```

To filter output with tools like `jq`:

```bash
./psjson | jq '.processes[] | select(.comm == "bash")'
```

## Output Format

The program outputs a JSON object with the following structure:

```json
{
  "processes": [
    {
      "pid": 1234,
      "comm": "process_name",
      "state": "R",
      "ppid": 1,
      "priority": 20,
      "nice": 0,
      "utime": 1234,
      "stime": 5678,
      "start_time": 9012,
      "vsize": 3456,
      "rss": 7890,
      "exe_path": "/path/to/executable"
    },
    ...
  ]
}
```

### Field Descriptions

- `pid`: Process ID
- `comm`: Command name
- `state`: Process state (R=running, S=sleeping, D=disk sleep, Z=zombie, etc.)
- `ppid`: Parent process ID
- `priority`: Scheduling priority
- `nice`: Nice value
- `utime`: User mode time
- `stime`: Kernel mode time
- `start_time`: Time the process started after system boot
- `vsize`: Virtual memory size
- `rss`: Resident set size
- `exe_path`: Full path to the executable

## Examples

### List all Firefox processes

```bash
./psjson | jq '.processes[] | select(.comm == "firefox")'
```

### Find processes using the most memory

```bash
./psjson | jq '.processes | sort_by(-.rss) | .[0:5]'
```

### Count processes by executable path

```bash
./psjson | jq '.processes | group_by(.exe_path) | map({path: .[0].exe_path, count: length}) | sort_by(-.count)'
```

## Notes

- The program needs to be run with appropriate permissions to access `/proc` information for all processes. For some processes owned by other users, you may need to run with elevated privileges.
- Some processes may not return a valid executable path if you don't have permissions to read their `/proc/PID/exe` symlink.

## License

This program is free software and can be redistributed and/or modified under the terms of your choosing.
