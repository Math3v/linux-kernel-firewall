#!/bin/bash
# spoustet jako root, priklady pouziti
# ./test.sh         	// spusti ten priklad co je v zadani, vypise diff (bez whitespaces) takze pokud se vam tam neco lisi, tak to uvidite
# ./test.sh [TCP|UDP|ICMP|DEBUG] // aby se slo divat do logu co se deje, tak je pred kazdou operaci nutne potvrtid Y a dat ENTER
# jsou to jednuduche testiky, jesli mate nekdo neco lepsiho, tak sem s tim :]

if [ $# == 0 ]; then
	echo -e "10 allow tcp from 147.229.1.1 to any dst-port 80\n20 allow udp from any to 8.8.8.8 src-port 53\n30 allow icmp from 147.229.1.1 to any\n40 deny ip from any to any" > tmp_rules
	#cat tmp_rules
	./pdscli -f tmp_rules
	./pdscli -a 15 allow tcp from 147.229.1.2 to any dst-port 8080
	./pdscli -d 30
	./pdscli -p > tmp_rules_out
	echo -e "
id   action 	srcip       	srcport 	dstip     	dstport 	protocol
10   allow  	147.229.1.1 	*       	*         	80      	tcp
15   allow  	147.229.1.2 	*       	*         	8080    	tcp
20   allow  	*           	53      	8.8.8.8   	*       	udp
40   deny   	*           	*       	*         	*       	ip" > tmp_rules_ok
	diff -w tmp_rules_out tmp_rules_ok
	rm tmp_rules tmp_rules_out tmp_rules_ok
else
	case "$1" in

	"TCP")
    	echo -n "Spustit TCP Test na wget seznamu: [y/n] "
    	read confirm
    	if [ "$confirm" == "y" ]; then   	 

        	echo -n "Spustit TCP Test 1a: -a 2 deny tcp from any to any [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	./pdscli -a 3 deny udp from any to any
        	fi
        	echo -n "Spustit TCP Test 1b: wget seznam.cz by nemelo fungovat [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	wget seznam.cz | wc -l
        	fi
        	echo -n "Spustit TCP Test 1c: -d 2 [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	./pdscli -d 3
        	fi
        	echo -n "Spustit TCP Test 1d: wget seznam.cz OK [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	wget seznam.cz | wc -l
        	fi

    	fi
    	;;
	"UDP")
    	echo -n "Spustit UDP Test na ping seznamu: [y/n] "
    	read confirm
    	if [ "$confirm" == "y" ]; then   	 

        	echo -n "Spustit UDP Test 1a: -a 1 deny udp from any to any [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	./pdscli -a 1 deny udp from any to any
        	fi
        	echo -n "Spustit UDP Test 1b: ping seznam.cz by nemelo fungovat [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	echo "cekej nekolik sekund"
        	ping -q -c 1 seznam.cz
        	fi
        	echo -n "Spustit UDP Test 1c: -d 1 [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	./pdscli -d 1
        	fi
        	echo -n "Spustit UDP Test 1d: ping seznam.cz OK [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	ping -q -c 1 seznam.cz
        	fi

    	fi
    	;;
	"ICMP")
    	echo -n "Spustit ICMP Test na ping 8.8.8.8: [y/n] "
    	read confirm
    	if [ "$confirm" == "y" ]; then   	 

        	echo -n "Spustit TCP Test 1a: -a 3 deny tcp from any to any [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	./pdscli -a 3 deny icmp from any to any
        	fi
        	echo -n "Spustit TCP Test 1b: ping 8.8.8.8 by nemelo fungovat [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	ping -q -c 1 "8.8.8.8"
        	fi
        	echo -n "Spustit TCP Test 1c: -d 3 [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	./pdscli -d 3
        	fi
        	echo -n "Spustit TCP Test 1d: ping 8.8.8.8 OK [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	ping -q -c 1 "8.8.8.8"
        	fi

    	fi
    	;;
    	"DEBUG")
    	echo -n "Spustit DEBUG Test: ruzna pravidla, s nutnosti potvrzeni, lze koukat do syslogu co se deje [y/n] "
    	read confirm
    	if [ "$confirm" == "y" ]; then   	 

        	echo -e "Spustit Test: ./pdscli -a \n10 allow tcp from 147.229.1.1 to any dst-port 80 [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	./pdscli -a 10 allow tcp from 147.229.1.1 to any dst-port 80
        	fi

        	echo -e "Spustit Test: ./pdscli -a \n20 allow udp from any to 8.8.8.8 src-port 53 [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	./pdscli -a 20 allow udp from any to 8.8.8.8 src-port 53
        	fi

        	echo -e "Spustit Test: ./pdscli -a \n30 allow icmp from 147.229.1.1 to any [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	./pdscli -a 30 allow icmp from 147.229.1.1 to any
        	fi

        	echo -n "Spustit Test: ./pdscli -d 21 // 21 neexistuje nic se nestane [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	echo -e "\nvolam: ./pdscli -d 21"
        	./pdscli -d 21
        	fi

        	echo -e "Spustit Test: ./pdscli -a \n40 deny ip from any to any -a [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	./pdscli -a 40 deny ip from any to any
        	fi

        	echo -e "Spustit Test: ./pdscli -a \n15 allow tcp from 147.229.1.2 to any dst-port 8080 -a [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	./pdscli -a 15 allow tcp from 147.229.1.2 to any dst-port 8080
        	fi

        	echo -e "Spustit Test: ./pdscli -a \n1 allow tcp from 147.229.1.2 to any dst-port 8080 -a [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	./pdscli -a 1 allow tcp from 123.123.123.123 to any
        	fi

        	echo -n "Spustit Test: ./pdscli -p [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	echo -e "\nvolam: ./pdscli -p"
        	./pdscli -p
        	fi

        	echo -n "Spustit Test: ./pdscli -d [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	echo -e "\nvolam: ./pdscli -d 30"
        	./pdscli -d 30
        	fi

        	echo -n "Spustit Test: ./pdscli -f [y/n] "
        	read confirm
        	if [ "$confirm" == "y" ]; then
        	echo -e "\nvolam: ./pdscli -f rules"
        	./pdscli -f rules
        	fi
       	 
        	echo -e "Mazu vsechna pravidla 0 - 100"
        	c=0
        	while [ $c -le 100 ]
        	do
            	./pdscli -d $c
            	(( c++ ))
        	done

    	fi
    	;;
	*) echo "Invalid param, try TCP, UDP, ICMP, DEBUG"
   	;;
	esac
   
fi

