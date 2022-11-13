# Autoreverse

If you are tired of googling "pentestmonkey reverse shell cheat sheet" copying and pasting the code and then configuring the IP and the port. THIS IS YOUR TOOL!!

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

```
autoreverse.py -I <network interface> -P <port> -p <payload> [-l] <listener> [-http] <http server port> [-a] <architecture>
```

![alt text](https://github.com/CronoX1/Pentestmonkey-Reverse-Shell/blob/main/images/autoreverse.png)

| Payload list  | 
| ------------- | 
|      PHP      | 
|     bash      |
|      war      |
|      nc       |
|     oldnc     |
|      exe      |
|      dll      |
|     python    |
|      ps1      |

## NOTES

If you have any idea to improve it, let me know!! 
