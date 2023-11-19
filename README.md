# SSN_db
Simple script that Xor and encode SSN table from https://hfiref0x.github.io/NT10_syscalls.html

The table from https://hfiref0x.github.io/NT10_syscalls.html is converted to json, xored, the functions names are reversed, then converted to base64 and written to data.jsonb.
Only the specified functions are stored to reduce json size. Default are : ["NtAllocateVirtualMemory","NtWriteVirtualMemory","NtCreateThreadEx"]

# Usage
usage: get_SSN.py [-h] [-a [APIS]]

optional arguments:
  -h, --help            show this help message and exit
  -a [APIS], --APIs [APIS]
                        comma separated list of API functions - case sensitive. Use All for default SSN.

# Note
read_json_xored function give an example of how the encoded SSN can be decoded.

# Reference 
https://hfiref0x.github.io/NT10_syscalls.html