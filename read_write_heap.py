#!/usr/bin/env python3
"""
Script to find and replace a string in the heap of a running process.

Usage: read_write_heap.py pid search_string replace_string
"""

import sys
import os


def read_write_heap(pid, search_string, replace_string):
    """
    Finds and replaces a string in the heap of a running process.

    Args:
        pid: The process ID.
        search_string: The string to search for.
        replace_string: The string to replace it with.
    """

    try:
        pid = int(pid)
        if pid <= 0:
            raise ValueError("PID must be a positive integer.")
    except ValueError as e:
        print(f"Error: Invalid PID: {e}", file=sys.stderr)
        sys.exit(1)

    maps_file_path = f"/proc/{pid}/maps"
    mem_file_path = f"/proc/{pid}/mem"

    try:
        with open(maps_file_path, "r") as maps_file:
            for line in maps_file:
                if "[heap]" in line:
                    heap_info = line.split()
                    # Format: start-end perms offset dev inode pathname
                    # Example: 00400000-00452000 rw-p 00000000 00:00 0  [heap]
                    address_range = heap_info[0].split("-")
                    start_address = int(address_range[0], 16)
                    end_address = int(address_range[1], 16)
                    permissions = heap_info[1]

                    if 'r' not in permissions or 'w' not in permissions:
                        print(f"Heap is not readable and/or writable. Permissions: {permissions}")
                        return

                    # Found the heap, now read and modify
                    with open(mem_file_path, "rb+") as mem_file:
                        try:
                            mem_file.seek(start_address)
                            heap_data = mem_file.read(end_address - start_address)
                        except OSError as e:
                            print(f"Error seeking or reading memory: {e}", file=sys.stderr)
                            sys.exit(1)

                        # Encode strings to bytes
                        search_bytes = search_string.encode('ascii')
                        replace_bytes = replace_string.encode('ascii')

                        # Check and handle different lengths
                        if len(replace_bytes) > len(search_bytes):
                             print(f"Error: Replacement string is longer than search string, and might cause memory corruption", file=sys.stderr)
                             sys.exit(1)
                        
                        # Pad replacement string with null bytes if it's shorter
                        if len(replace_bytes) < len(search_bytes):
                            replace_bytes += b'\x00' * (len(search_bytes) - len(replace_bytes))
                            
                         # Find the string and replace
                        index = heap_data.find(search_bytes)
                        if index != -1:
                            mem_file.seek(start_address + index)
                            mem_file.write(replace_bytes)
                            print(f"String '{search_string}' found and replaced with '{replace_string}' at heap address {hex(start_address + index)}")
                            return
                        else:
                            print(f"String '{search_string}' not found in heap.")
                            return
            print(f"Heap not found for PID {pid}.")


    except FileNotFoundError:
        print(f"Error: Process with PID {pid} not found or /proc/{pid}/maps does not exist.", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied.  You may need root privileges to access /proc/{pid}/mem.", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
         print(f"Error: An OS error occurred: {e}", file=sys.stderr)
         sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)



if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: read_write_heap.py pid search_string replace_string", file=sys.stderr)
        sys.exit(1)

    pid = sys.argv[1]
    search_string = sys.argv[2]
    replace_string = sys.argv[3]

    read_write_heap(pid, search_string, replace_string)