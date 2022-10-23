# Autoreverse

If you are tired of googling "pentestmonkey reverse shell cheat sheet" copying and pasting the code and then configuring the IP and the port. THIS IS YOUR TOOL!!

## Requirements

You will need to have "xclip" installed. If you don't have it, install it with this:

```
pip3 install simple_colors
```

## How to install it

1. Download the script

```
wget https://raw.githubusercontent.com/CronoX1/autoreverse/main/autoreverse.py
```

2. Create a symbolic link to use the tool in all directories

```
ln -s /full/path/of/autoreverse.py /usr/local/bin/autoreverse.py
```
## Usage

```
autoreverse.py -I <network interface> -P <Port> -p <payload> -l <listener>
```

![alt text](https://github.com/CronoX1/Pentestmonkey-Reverse-Shell/blob/main/images/usage.png)

## NOTES

If you have any idea to improve it, let me know!! 
