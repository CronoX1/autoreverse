# Autoreverse

This tool configure different payloads so you don't have to do it manually.

## Requirements

You will need to have "simple_colors" and "rlwrap" installed. If you don't have it, install it with this:

```
pip3 install simple_colors && sudo apt-get install rlwrap
```

## How to install it

1. Download the script.

```
wget https://raw.githubusercontent.com/CronoX1/autoreverse/main/autoreverse.py
```


## Usage


|     Flag      |  Description  |
| ------------- | ------------- |
| -I, --interface   | Network Interface of the IP address you want to configure the payload  |
| -P, --port  | The port you want to use on the payload  |
| -p, --payload  | The payload you want to use (php, bash, nc, oldnc, exe, dll, ps1, elf, war, apsx or python)  |
| -l, --listener (optional)  | Create a listener on nc (netcat) or msf (meterpreter) |
| -a, --architecture (optional) | Choose the architecture of the system (x86 = 32bits, x64 = 64bits) default value is x64. |
| -http, --httpserver (optional) | Create an HTTP server to upload the file with command injection  |

### Example

```
autoreverse.py -I <network interface> -P <port> -p <payload> [-l] <listener> [-http] <http server port> [-a] <architecture>
```

![alt text](https://github.com/CronoX1/Pentestmonkey-Reverse-Shell/blob/main/images/autoreverse.png)

## NOTES

If you have any idea to improve it, let me know!! 
