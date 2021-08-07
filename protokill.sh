#!/bin/bash
#PUTO EL QUE LO DESENCRIPTA
#colores
lor1='\033[1;31m';lor2='\033[1;32m';lor3='\033[1;33m';lor4='\033[1;34m';lor5='\033[1;35m';lor6='\033[1;36m';lor7='\033[1;37m'

## VERIFICACION IP ACA COMIENZA
#IP=$(wget -qO- whatismyip.akamai.com)
#[[ "$IP" = "" ]]&& IP="errorp"
#PASS=$(wget -qO- https://www.dropbox.com/s/f32yosi8zoiwkme/listip.txt |grep "$IP" |awk -F : {'print $1'})
#rm -rf instalador.sh
#if [ "$IP" = "$PASS" ]; then
#clear
#else
#echo -e "${lor1} ACCESO NO PERMITIDO PEDIME A ${lor6}@killshito ${lor7}"
#exit
#exit 0
#fi
## TERMINA LA VERIFICACION


if [ $(id -u) -eq 0 ];then
clear
else
echo -e "Run the script as user${lor2}root${lor7}"
exit
fi 
[ -f /usr/bin/vps-mx ]&&echo -e "${lor1}THIRD PARTY SCRIPT DETECTED"&& exit 
[ -f /usr/bin/adm ]&&echo -e "${lor1}THIRD PARTY SCRIPT DETECTED"&& exit 
[ -f /bin/menu ]&&echo -e "${lor1}THIRD PARTY SCRIPT DETECTED"&& exit 
[ -f /etc/newadm/menu ]&&echo -e "${lor1}THIRD PARTY SCRIPT DETECTED"&& exit 
fun_bar () {
          comando[0]="$1"
          comando[1]="$2"
          (
          [[ -e $HOME/fim ]] && rm $HOME/fim
          ${comando[0]} > /dev/null 2>&1
          ${comando[1]} > /dev/null 2>&1
          touch $HOME/fim
          ) > /dev/null 2>&1 &
          tput civis
		  echo -e "${lor6}---------------------------------------------------${lor7}"
          echo -ne "${lor7}    WAIT..${lor1}["
          while true; do
          for((i=0; i<18; i++)); do
          echo -ne "${lor5}#"
          sleep 0.2s
          done
         [[ -e $HOME/fim ]] && rm $HOME/fim && break
         echo -e "${col5}"
         sleep 1s
         tput cuu1
         tput dl1
         echo -ne "${lor7}    WAIT..${lor1}["
         done
         echo -e "${lor1}]${lor7} -${lor7} FINISHED ${lor7}"
         tput cnorm
		 echo -e "${lor6}---------------------------------------------------${lor7}"
        }
		
banner="      ___           _              _ _ _ 
     / _ \_ __ ___ | |_ ___   /\ /(_) | |
    / /_)/ '__/ _ \| __/ _ \ / //_/ | | |
   / ___/| | | (_) | || (_) / __ \| | | |
   \/    |_|  \___/ \__\___/\/  \/|_|_|_| "

espe () {   
echo -e "${lor7}"
read -p " Enter to Continue.."
}  
while true; do
clear&&clear
cd /root/ 
if netstat -nltp|grep 'badvpn-udpgw' > /dev/null; then
badudp=$(netstat -nplt |grep 'badvpn-udpgw' | awk -F ":" {'print $2'} | cut -d " " -f 1 | xargs)
else
badudp=$(echo -e "${lor1}not available")
fi  
if netstat -nltp|grep 'python' > /dev/null; then
pyho=$(netstat -nplt |grep 'python' | awk -F ":" {'print $2'} | cut -d " " -f 1 | xargs)
else
pyho=$(echo -e "${lor1}not available")
fi  
if netstat -nltp|grep 'stunnel4' > /dev/null; then
ssl=$(netstat -nplt |grep 'stunnel4' | awk -F ":" {'print $2'} | cut -d " " -f 1 | xargs)
else
ssl=$(echo -e "${lor1}not available")
fi 
echo -e "${lor4}***************************************************${lor7}"
echo -e "${lor2}  Group |${lor7} âœ¹âšœï¸ï´¾LEGION KINGï´¿âšœï¸âœ¹SÑ”rvÑ”â„œ y memesðŸ¸ðŸ™ˆ    "
echo -e "${lor1}===================================================${lor7} "
echo -e "${lor4}$banner ${lor7}"
echo -e "${lor7}      Mini Script Panel created by @KillShito "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”${lor5}â€”â€”â€”â€”â€”â€”â€”â€”â€”${lor1}â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
echo -e "${lor6}   BADVPN:${lor7} $badudp"
echo -e "${lor6}   PYTHON:${lor7} $pyho  "
echo -e "${lor6}   SSL:${lor7}    $ssl   "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”${lor5}â€”â€”â€”â€”â€”â€”â€”â€”â€”${lor1}â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
echo -e "${lor7}[${lor2}1${lor7}] ${lor3}==>${lor7} SEE SSH CONNECTORS "
echo -e "${lor7}[${lor2}2${lor7}] ${lor3}==>${lor7} USER RECORDS  "
echo -e "${lor7}[${lor2}3${lor7}] ${lor3}==>${lor7} SYSTEM INFORMATION "
echo -e "${lor7}[${lor2}4${lor7}] ${lor3}==>${lor7} ADD / REMOVE / RENEW USERS"
echo -e "${lor7}-----------------${lor6}PROTOCOL MANAGEMENT${lor7}---------------${lor7}"
echo -e "${lor7}[${lor2}5${lor7}] ${lor3}==>${lor7} BADVPN MANAGER      "
echo -e "${lor7}[${lor2}6${lor7}] ${lor3}==>${lor7} START PROXY PYTHON  "
echo -e "${lor7}[${lor2}7${lor7}] ${lor3}==>${lor7} SSL STUNNEL MANAGER "
echo -e "${lor7}-----------------------${lor6}EXTRAS${lor7}----------------------${lor7}"
echo -e "${lor7}[${lor2}8${lor7}] ${lor3}==>${lor7} CREDITS "
echo -e "${lor7}[${lor2}9${lor7}] ${lor3}==>${lor7} EXIT THE PANEL "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
unset opc
while [[ -z ${opc} ]]; do	
read -p "SELECT OPTION :" opc
tput cuu1
tput dl1
done
case $opc in

1)clear&&clear
echo -e "${lor4}***************************************************${lor7}"
echo -e "${lor2}                  SEE SSH CONNECTORS "
echo -e "${lor1}===================================================${lor7} "
echo -e "${lor4}$banner ${lor7}"
echo -e "${lor7}      Mini Script Panel created by @KillShito "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
data="/etc/prokill/database"
tmp_now=$(printf '%(%H%M%S)T\n')
fundrop () {
port_dropbear=`ps aux | grep dropbear | awk NR==1 | awk '{print $17;}'`
log=/var/log/auth.log
loginsukses='Password auth succeeded'
clear
pids=`ps ax |grep dropbear |grep  " $port_dropbear" |awk -F" " '{print $1}'`
for pid in $pids
do
pidlogs=`grep $pid $log |grep "$loginsukses" |awk -F" " '{print $3}'`
i=0
for pidend in $pidlogs
do
let i=i+1
done
    if [ $pidend ];then
       login=`grep $pid $log |grep "$pidend" |grep "$loginsukses"`
       PID=$pid
       user=`echo $login |awk -F" " '{print $10}' | sed -r "s/'/ /g"`
       gph=`echo $login |awk -F" " '{print $2"-"$1,$3}'`
       while [ ${#gph} -lt 13 ]; do
           gph=$gph" "
       done
       while [ ${#user} -lt 16 ]; do
           user=$user" "
       done
       while [ ${#PID} -lt 8 ]; do
           PID=$PID" "
       done
       echo "$user $PID $gph"
    fi
done
}
echo -e "${lor7}      Users      Connection     Time Connects   "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"

 while read usline
    do  
        user="$(echo $usline | cut -d' ' -f1)"
        if [ "$(cat /etc/passwd| grep -w $user| wc -l)" = "1" ]; then
          sqd="$(ps -u $user | grep sshd | wc -l)"
        else
          sqd=00
        fi
        [[ "$sqd" = "" ]] && sqd=0
        if [[ -e /etc/openvpn/openvpn-status.log ]]; then
          ovp="$(cat /etc/openvpn/openvpn-status.log | grep -E ,"$user", | wc -l)"
        else
          ovp=0
        fi
        if netstat -nltp|grep 'dropbear'> /dev/null;then
          drop="$(fundrop | grep "$user" | wc -l)"
        else
          drop=0
        fi
        cnx=$(($sqd + $drop))
        conec=$(($cnx + $ovp))
        if [[ $cnx -gt 0 ]]; then
          tst="$(ps -o etime $(ps -u $user |grep sshd |awk 'NR==1 {print $1}')|awk 'NR==2 {print $1}')"
          tst1=$(echo "$tst" | wc -c)
        if [[ "$tst1" == "9" ]]; then 
          timerg="$(ps -o etime $(ps -u $user |grep sshd |awk 'NR==1 {print $1}')|awk 'NR==2 {print $1}')"
        else
          timerg="$(echo "00:$tst")"
        fi
        elif [[ $ovp -gt 0 ]]; then
          tmp2=$(printf '%(%H:%M:%S)T\n')
          tmp1="$(grep -w "$user" /etc/openvpn/openvpn-status.log |awk '{print $4}'| head -1)"
          [[ "$tmp1" = "" ]] && tmp1="00:00:00" && tmp2="00:00:00"
          var1=`echo $tmp1 | cut -c 1-2`
          var2=`echo $tmp1 | cut -c 4-5`
          var3=`echo $tmp1 | cut -c 7-8`
          var4=`echo $tmp2 | cut -c 1-2`
          var5=`echo $tmp2 | cut -c 4-5`
          var6=`echo $tmp2 | cut -c 7-8`
          calc1=`echo $var1*3600 + $var2*60 + $var3 | bc`
          calc2=`echo $var4*3600 + $var5*60 + $var6 | bc`
          seg=$(($calc2 - $calc1))
          min=$(($seg/60))
          seg=$(($seg-$min*60))
          hor=$(($min/60))
          min=$(($min-$hor*60))
          timerusr=`printf "%02d:%02d:%02d \n" $hor $min $seg;`
          timerg=$(echo "$timerusr" | sed -e 's/[^0-9:]//ig' )
        else
          timerg="00:00:00"
        fi
		while [[ ${#user} -lt 13 ]]; do
        user=$user" "
        done
		while [[ ${#conec} -lt 12 ]]; do
        conec=$conec" "
        done		
        if [[ $conec -eq 0 ]]; then
        
           echo -e "${lor1}    $user    ${lor7}$conec  $timerg "
        else
           echo -e "${lor2}    $user    ${lor7}$conec  $timerg "
        fi
        echo -e "${lor6}---------------------------------------------------${lor7}"
    done < "$data"
espe	
;;
2)clear&&clear
echo -e "${lor4}***************************************************${lor7}"
echo -e "${lor2}                    USER RECORDS  "
echo -e "${lor1}===================================================${lor7} "
echo -e "${lor4}$banner ${lor7}"
echo -e "${lor7}      Mini Script Panel created by @KillShito "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
VPSsec=$(date +%s)
touch /etc/prokill/database
data="/etc/prokill/database"
RETURN="$(cat $data|cut -d'|' -f1)"
USERS="$(cat $data|cut -d'|' -f1)"
while read hostreturn ; do
DateExp="$(cat /etc/prokill/database|grep -w "$hostreturn"|cut -d'|' -f3)"
if [[ ! -z $DateExp ]]; then             
DataSec=$(date +%s --date="$DateExp")
[[ "$VPSsec" -gt "$DataSec" ]] && EXPTIME="\e[91m[EXPIRED]\e[97m" || EXPTIME="\e[92m$(($(($DataSec - $VPSsec)) / 86400)) Days"
else
EXPTIME="\e[91m[ S/R ]"
fi 
pass="$(cat /etc/prokill/database|grep -w "$hostreturn"|cut -d'|' -f2)"
 while [[ ${#hostreturn} -lt 10 ]]; do
 hostreturn=$hostreturn" "
 done
 while [[ ${#pass} -lt 10 ]]; do
 pass=$pass" "
 done
 while [[ ${#DateExp} -lt 15 ]]; do
 DateExp=$DateExp" "
 done
 while [[ ${#EXPTIME} -lt 15 ]]; do
 EXPTIME=$EXPTIME" "
 done 
echo -e "\e[97m $hostreturn $pass ${lor3}$DateExp $EXPTIME"
echo -e "${lor6}---------------------------------------------------${lor7}"
done <<< "$USERS"
espe
;;

3)clear&&clear
echo -e "${lor4}***************************************************${lor7}"
echo -e "${lor2}                 SYSTEM INFORMATION  "
echo -e "${lor1}===================================================${lor7} "
echo -e "${lor4}$banner ${lor7}"
echo -e "${lor7}      Mini Script Panel created by @KillShito "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
if [ -f /etc/lsb-release ];then
echo -e "${lor3} OPERATING SYSTEM "
echo 
name=$(cat /etc/lsb-release |grep DESCRIPTION |awk -F = {'print $2'})
codename=$(cat /etc/lsb-release |grep CODENAME |awk -F = {'print $2'})
echo -e "${lor6}Nombre: ${lor7}$name"
echo -e "${lor6}CodeName: ${lor7}$codename"
echo -e "${lor6}Kernel: ${lor7}$(uname -s)"
echo -e "${lor6}Kernel Release: ${lor7}$(uname -r)"
if [ -f /etc/os-release ]
then
devlike=$(cat /etc/os-release |grep LIKE |awk -F = {'print $2'})
echo -e "${lor6}Derived from OS: \033[1;37m$devlike"
echo ""
fi
else
system=$(cat /etc/issue.net)
echo -e "${lor3} OPERATING SYSTEM "
echo 
echo -e "${lor6}Name: ${lor7}$system"
echo ""
fi
if [ -f /proc/cpuinfo ];then
echo -e "${lor3} PROCESSOR "
echo 
uso=$(top -bn1 | awk '/Cpu/ { cpu = "" 100 - $8 "%" }; END { print cpu }')
modelo=$(cat /proc/cpuinfo |grep "model name" |uniq |awk -F : {'print $2'})
cpucores=$(grep -c cpu[0-9] /proc/stat)
cache=$(cat /proc/cpuinfo |grep "cache size" |uniq |awk -F : {'print $2'})
clock=$(lscpu | grep "CPU MHz" | awk '{print $3}')
echo -e "${lor6}Model:${lor7}$modelo"
echo -e "${lor6}Nuclei:${lor7} $cpucores"
echo -e "${lor6}Memory cache:${lor7}$cache"
echo -e "${lor6}Architecture: ${lor7}$(uname -p)"
echo -e "${lor6}Used: ${lor7}$uso"
echo -e "${lor6}Clock: ${lor7}$clock MHz"
echo ""
else
echo -e "${lor3} PROCESSADOR "
echo 
echo ""
echo -e "${lor1}Information could not be obtained"
fi
if free 1>/dev/null 2>/dev/null;then
ram1=$(free -h | grep -i mem | awk {'print $2'})
ram2=$(free -h | grep -i mem | awk {'print $4'})
ram3=$(free -h | grep -i mem | awk {'print $3'})
usoram=$(free -m | awk 'NR==2{printf "%.2f%%\t\t", $3*100/$2 }')
echo -e "${lor3} MEMORY RAM "
echo
echo -e "${lor6}Total: ${lor7}$ram1"
echo -e "${lor6}In use: ${lor7}$ram3"
echo -e "${lor6}Free: ${lor7}$ram2"
echo -e "${lor6}Used: ${lor7}$usoram"
echo ""
else
echo -e "${lor3} MEMORY RAM "
echo 
echo -e "${lor1}Information could not be obtained"
echo
fi
espe
;;
4)clear&&clear
echo -e "${lor4}***************************************************${lor7}"
echo -e "${lor2}            ADD / REMOVE / RENEW USERS "
echo -e "${lor1}===================================================${lor7} "
echo -e "${lor4}$banner ${lor7}"
echo -e "${lor7}      Mini Script Panel created by @KillShito "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
echo -e "${lor7}[${lor2}1${lor7}] ${lor3}==>${lor7} ADD USER "
echo -e "${lor7}[${lor2}2${lor7}] ${lor3}==>${lor7} REMOVE USER "
echo -e "${lor7}[${lor2}3${lor7}] ${lor3}==>${lor7} RENEW USER "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
read -p "SELECT OPTION :" opci
echo
if [ "$opci" = "1" ];then
read -p " # Username :" name
awk -F : ' { print $1 }' /etc/passwd > /tmp/users 
if grep -Fxq "$name" /tmp/users;then
echo -e "${lor1} This user already exists ${lor7}"  	
else
if (echo $name | egrep [^a-zA-Z0-9.-_] &> /dev/null);then 
echo -e "${lor1} Invalid username ${lor7}" 
else
if [[ -z $name ]];then
echo -e "${lor1} Empty username ${lor7}" 
else
sizemin=$(echo ${#name})
if [[ $sizemin -lt 2 ]];then
echo -e "${lor1} Very short username ${lor7}" 
else
sizemax=$(echo ${#name})
if [[ $sizemax -gt 15 ]];then
echo -e "${lor1} Very large username ${lor7}" 
else	
read -p " # Password :" pass
if [[ -z $pass ]];then
echo -e "${lor1} Empty password ${lor7}" 
else
sizepass=$(echo ${#pass})
if [[ $sizepass -lt 5 ]];then
echo -e "${lor1} Very short password ${lor7}" 
else	
read -p " # Days to expire: " days
if (echo $days | egrep '[^0-9]' &> /dev/null);then
echo -e "${lor1} Invalid number of days" 
else
if [[ -z $days ]];then
echo -e "${lor1} Number of days empty ${lor7}" 
else	
if [[ $days -lt 1 ]];then
echo -e "${lor1} Number of days greater than zero ${lor7}"
else 
valid=$(date '+%C%y-%m-%d' -d " +$days days")
datespi=$(date "+%Y/%m/%d" -d " +$days days")
useradd -M -s /bin/false $name -e $valid
(echo $pass; echo $pass)|passwd $name 2>/dev/null
echo "$name | $pass | $datespi" >> /etc/prokill/database
IPSEC=$(wget -qO- whatismyip.akamai.com)
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
echo -e "${lor3} *${lor7} IP              : $IPSEC    "
echo -e "${lor3} *${lor7} User            : $name  " 
echo -e "${lor3} *${lor7} Password        : $pass  "
echo -e "${lor3} *${lor7} Expiration date : $datespi  " 
fi;fi;fi;fi;fi;fi;fi;fi;fi;fi
fi

if [ "$opci" = "2" ];then
clear&&clear
echo -e "${lor4}***************************************************${lor7}"
echo -e "${lor2}                  SEE SSH CONNECTORS "
echo -e "${lor1}===================================================${lor7} "
echo -e "${lor4}$banner ${lor7}"
echo -e "${lor7}      Mini Script Panel created by @KillShito "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
sds=$(cat /etc/prokill/database |grep -c "|"|awk 'NR==1')
if [ "$sds" = "0" ]; then
echo -e "${lor1}                 NO REGISTERED USERS "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
else
echo -e "${lor7}                       User List "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
userss () {
for u in `cat /etc/prokill/database|awk -F "|" '{print $1}'`; do
echo "$u"
done
}			
assets=($(userss))
i=0
for us in $(echo ${assets[@]}); do
ed=$(cat /etc/prokill/database|grep -w "$us" |awk  '{print $5}')
echo -e "${lor7}[${lor2}$i${lor7}]${lor1} -> ${lor6}${us} -                ${lor7}REMOVE" 
     let i++
     done
	 echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
     echo -ne "${lor7}REMOVE USER : " && read selection
     tput cuu1
     tput dl1
     if [[ -z ${selection} ]]; then
     nada=$nada
     else
     userdil="${assets[$selection]}"
     fi	 
userdel --force $userdil > /dev/null 2>/dev/null			
if [ -e /etc/prokill/database ]; then
grep -v ^$userdil[[:space:]] /etc/prokill/database > /tmp/ph ; cat /tmp/ph > /etc/prokill/database
fi
echo -e "${lor3}               USER $userdil WAS DELETED ${lor7}"

fi
fi

if [ "$opci" = "3" ];then
clear&&clear
echo -e "${lor4}***************************************************${lor7}"
echo -e "${lor2}                  SEE SSH CONNECTORS "
echo -e "${lor1}===================================================${lor7} "
echo -e "${lor4}$banner ${lor7}"
echo -e "${lor7}      Mini Script Panel created by @KillShito "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
sds=$(cat /etc/prokill/database |grep -c "|"|awk 'NR==1')
if [ "$sds" = "0" ]; then
echo -e "${lor1}                 NO REGISTERED USERS "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
else
echo -e "${lor7}                       User List "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
userss () {
for u in `cat /etc/prokill/database|awk -F "|" '{print $1}'`; do
echo "$u"
done
}			
assets=($(userss))
i=0
for us in $(echo ${assets[@]}); do
ed=$(cat /etc/prokill/database|grep -w "$us" |awk  'NR==1{print $5}')
echo -e "${lor7}[${lor2}$i${lor7}]${lor1} -> ${lor6}${us} -                ${lor7}${ed}" 
     let i++
     done
	 echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
     echo -ne "${lor7}RENEW USER : " && read selection
     tput cuu1
     tput dl1
     if [[ -z ${selection} ]]; then
     nada=$nada
     else
     userdil="${assets[$selection]}"
     fi	 
echo
read -p "Renew User $userdil for days : " inputdate
fetch=$(date "+%d/%m/%Y" -d " +$inputdate days")
fetch2=$(date "+%Y/%m/%d" -d " +$inputdate days")
sysdate="$(echo "$fetch" | awk -v FS=/ -v OFS=- '{print $3,$2,$1}')"
if (date "+%Y-%m-%d" -d "$sysdate" > /dev/null  2>&1);then
if [[ -z $fetch ]];then
echo ""
echo -e "${lor1}You have entered an invalid or non-existent date${lor7}" 
else
if (echo $fetch | egrep [^a-zA-Z] &> /dev/null);then
today="$(date -d today +"%Y%m%d")"
timemachine="$(date -d "$sysdate" +"%Y%m%d")"
if [ $today -ge $timemachine ]; then
echo -e "${lor1}You have entered a past date or the current day${lor1}" 
else
chage -E $sysdate $userdil
echo ;echo -e "${lor2}USER $userdil WAS RENEWED FOR THE DAYS $fetch2"
dataus=$(cat /etc/prokill/database |awk '{print $1,$2,$3,$4}')
grep -v ^$userdil[[:space:]] /etc/prokill/database > /tmp/ph ; cat /tmp/ph > /etc/prokill/database
echo "$dataus $fetch2" >> /etc/prokill/database
fi;fi;fi;fi;fi
fi
espe
;;
5)clear&&clear
echo -e "${lor4}***************************************************${lor7}"
echo -e "${lor2}                   BADVPN MANAGER "
echo -e "${lor1}===================================================${lor7} "
echo -e "${lor4}$banner ${lor7}"
echo -e "${lor7}      Mini Script Panel created by @KillShito "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
[[ $(netstat -nplt |grep 'badvpn-udpgw') ]] && badvp="STOP SERVICE ${lor2}ON" || badvp="START SERVICE ${lor1}OFF"
echo -e "${lor7}[${lor2}1${lor7}] ${lor3}==>${lor7} INSTALL BADVPN"
echo -e "${lor7}[${lor2}2${lor7}] ${lor3}==>${lor7} UNINSTALL BADVPN "
echo -e "${lor7}[${lor2}3${lor7}] ${lor3}==>${lor7} $badvp "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
read -p "SELECT OPTION :" opci
if [ "$opci" = "1" ];then
if [ -f /bin/badvpn-udpgw ];then
echo;echo -e "${lor1} BADVPN IS ALREADY INSTALLED "
else
echo;echo -e "${lor3}              CONFIGURING BADVPN..  "
badvpn (){
wget https://www.dropbox.com/s/t2v7fy4ole7tndm/badvpn-udpgw
mv badvpn-udpgw /bin/badvpn-udpgw
chmod 777 /bin/badvpn-udpgw
sed -i '$d' /etc/rc.local
echo "/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10 &" >> /etc/rc.local 
echo "exit 0" >> /etc/rc.local 
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10 
}
fun_bar 'badvpn'
echo;echo -e "${lor2} BADVPN INSTALLED "
fi
fi
if [ "$opci" = "2" ];then
if [ -f /bin/badvpn-udpgw ];then
for pid in $(pgrep badvpn-udpgw);do
kill $pid
done
rm -rf /bin/badvpn-udpgw
echo;echo -e "${lor2} BADVPN WAS REMOVED "
else
echo;echo -e "${lor1} BADVPN IS NOT INSTALLED "
fi;fi
if [ "$opci" = "3" ];then
if [ -f /bin/badvpn-udpgw ];then
if netstat -nltp|grep 'badvpn-udpgw' > /dev/null; then
for pid in $(pgrep badvpn-udpgw);do
kill $pid
done
echo;echo -e "${lor1} SERVICE STOPPED "
else
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10
echo;echo -e "${lor2} SERVICE STARTED "
fi
else
echo;echo -e "${lor1} BADVPN IS NOT INSTALLED "
fi
fi
espe
;;
6)clear&&clear
echo -e "${lor4}***************************************************${lor7}"
echo -e "${lor2}                    PROXY PYTHON "
echo -e "${lor1}===================================================${lor7} "
echo -e "${lor4}$banner ${lor7}"
echo -e "${lor7}      Mini Script Panel created by @KillShito "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
echo -e "${lor7}[${lor2}1${lor7}] ${lor3}==>${lor7} START PROXY"
echo -e "${lor7}[${lor2}2${lor7}] ${lor3}==>${lor7} STOP PYTHON SERVICE "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
read -p "SELECT OPTION :" opci
if [ "$opci" = "1" ];then
pt=$(netstat -nplt |grep 'sshd' | awk -F ":" NR==1{'print $2'} | cut -d " " -f 1)
echo;echo -e "${lor7} Local port  ${lor6}"
read -p " :" -e -i $pt PT
echo;echo -e "${lor7} Listen-proxy  ${lor6}"
read -p " :" ptg
stus="101"
[ "$ptg" = "8080" ]&& stus="200"
if [ -z $ptg ]; then
echo;echo -e "${lor1}  INVALID PORT"  
else 
if (echo $ptg | egrep '[^0-9]' &> /dev/null);then
echo;echo -e "${lor1}  YOU MUST ENTER A NUMBER" 
else
if lsof -Pi :$ptg -sTCP:LISTEN -t >/dev/null ; then
echo;echo -e "${lor1}  THE PORT IS ALREADY IN USE"  
else
echo;echo -e "${lor7} Banner Message ${lor6}"
read -p " :" -e -i "<font color="red">ProtoKill Script</font>" msgbanner
cat <<EOF > /tmp/proxy.py
import socket, threading, thread, select, signal, sys, time, getopt

# CONFIG
LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = 1080
PASS = ''

# CONST
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = "127.0.0.1:$PT"
RESPONSE = 'HTTP/1.1 $stus $msgbanner \r\n\r\n'
 
class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
	self.threadsLock = threading.Lock()
	self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True

        try:                    
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue
                
                conn = ConnectionHandler(c, self, addr)
                conn.start();
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()
            
    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()
	
    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()
                    
    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()
                
    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()
            
            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()
			

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True
            
        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)
        
            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')
            
            if hostPort == '':
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')

            if split != '':
                self.client.recv(BUFLEN)
            
            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
	    pass
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        aux = head.find(header + ': ')
    
        if aux == -1:
            return ''

        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')

        if aux == -1:
            return ''

        return head[:aux];

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 443
            else:
                port = 80

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path
        
        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''

        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
		    try:
                        data = in_.recv(BUFLEN)
                        if data:
			    if in_ is self.target:
				self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]

                            count = 0
			else:
			    break
		    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True

            if error:
                break


def print_usage():
    print 'Usage: proxy.py -p <port>'
    print '       proxy.py -b <bindAddr> -p <port>'
    print '       proxy.py -b 0.0.0.0 -p 1080'

def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT
    
    try:
        opts, args = getopt.getopt(argv,"hb:p:",["bind=","port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)
    

def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    
    print "\n ==============================\n"
    print "\n         PYTHON PROXY          \n"
    print "\n ==============================\n"
    print "corriendo ip: " + LISTENING_ADDR
    print "corriendo port: " + str(LISTENING_PORT) + "\n"
    print "Se ha Iniciado Por Favor Cierre el Terminal\n"
    
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()

    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print 'Stopping...'
            server.close()
            break
    
if __name__ == '__main__':
    parse_args(sys.argv[1:])
    main()
EOF
screen -dmS pythonwe python /tmp/proxy.py -p $ptg &> /dev/null

echo;echo -e "${lor2} PORT $ptg INITIATED"
fi;fi;fi

fi
if [ "$opci" = "2" ];then
for pid in $(pgrep python);do
kill $pid
done
echo;echo -e "${lor1} PROXY PYTHON WAS DETAINED"
fi
espe
;;
7)clear&&clear
echo -e "${lor4}***************************************************${lor7}"
echo -e "${lor2}                 SSL STUNNEL MANAGER "
echo -e "${lor1}===================================================${lor7} "
echo -e "${lor4}$banner ${lor7}"
echo -e "${lor7}      Mini Script Panel created by @KillShito "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
[[ $(netstat -nplt |grep 'stunnel4') ]] && sessl="STOP SERVICE ${lor2}ON" || sessl="START SERVICE ${lor1}OFF"
echo -e "${lor7}[${lor2}1${lor7}] ${lor3}==>${lor7} INSTALL SSL STUNNEL"
echo -e "${lor7}[${lor2}2${lor7}] ${lor3}==>${lor7} UNINSTALL SSL STUNNEL "
echo -e "${lor7}[${lor2}3${lor7}] ${lor3}==>${lor7} ADD NEW PORT "
echo -e "${lor7}[${lor2}4${lor7}] ${lor3}==>${lor7} $sessl "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
read -p "SELECT OPTION :" opci
if [ "$opci" = "1" ];then
if [ -f /etc/stunnel/stunnel.conf ]; then
echo;echo -e "${lor1}  ALREADY INSTALLED" 
else
echo;echo -e "${lor7} Local port  ${lor6}"
pt=$(netstat -nplt |grep 'sshd' | awk -F ":" NR==1{'print $2'} | cut -d " " -f 1)
read -p " :" -e -i $pt PT
echo;echo -e "${lor7} Listen-SSL  ${lor6}"
read -p " :" sslpt
if [ -z $sslpt ]; then
echo;echo -e "${lor1}  INVALID PORT"  
else 
if (echo $sslpt | egrep '[^0-9]' &> /dev/null);then
echo;echo -e "${lor1}  YOU MUST ENTER A NUMBER" 
else
if lsof -Pi :$sslpt -sTCP:LISTEN -t >/dev/null ; then
echo;echo -e "${lor1}  THE PORT IS ALREADY IN USE"  
else
inst_ssl () {
apt-get purge stunnel4 -y 
apt-get purge stunnel -y
apt-get install stunnel -y
apt-get install stunnel4 -y
pt=$(netstat -nplt |grep 'sshd' | awk -F ":" NR==1{'print $2'} | cut -d " " -f 1)
echo -e "cert = /etc/stunnel/stunnel.pem\nclient = no\nsocket = a:SO_REUSEADDR=1\nsocket = l:TCP_NODELAY=1\nsocket = r:TCP_NODELAY=1\n\n[stunnel]\nconnect = 127.0.0.1:${PT}\naccept = ${sslpt}" > /etc/stunnel/stunnel.conf
openssl genrsa -out key.pem 2048 > /dev/null 2>&1
(echo br; echo br; echo uss; echo speed; echo pnl; echo killshito; echo @killshito.com)|openssl req -new -x509 -key key.pem -out cert.pem -days 1095 > /dev/null 2>&1
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
rm -rf key.pem;rm -rf cert.pem
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
service stunnel4 restart
service stunnel restart
service stunnel4 start
}
fun_bar 'inst_ssl'
echo;echo -e "${lor2}  SSL STUNNEL INSTALLED " 
fi;fi;fi;fi
fi
if [ "$opci" = "2" ];then
del_ssl () {
service stunnel4 stop
apt-get remove stunnel4 -y
apt-get purge stunnel4 -y
apt-get purge stunnel -y
rm -rf /etc/stunnel
rm -rf /etc/stunnel/stunnel.conf
rm -rf /etc/default/stunnel4
rm -rf /etc/stunnel/stunnel.pem
}
fun_bar 'del_ssl'
echo;echo -e "${lor2}  SSL STUNNEL WAS REMOVED " 
fi
if [ "$opci" = "3" ];then
if [ -f /etc/stunnel/stunnel.conf ]; then 
echo;echo -e "${lor7}Enter a name for the SSL Redirector${lor6}"
read -p " :" -e -i stunnel namessl
echo;echo -e "${lor7}Enter the port of the Service to bind${lor6}"
pt=$(netstat -nplt |grep 'sshd' | awk -F ":" NR==1{'print $2'} | cut -d " " -f 1)
read -p " :" -e -i $pt PT
echo;echo -e "${lor7}Enter the New SSL Port${lor6}"
read -p " :" sslpt
if [ -z $sslpt ]; then
echo;echo -e "${lor1}  INVALID PORT"  
else 
if (echo $sslpt | egrep '[^0-9]' &> /dev/null);then
echo;echo -e "${lor1}  YOU MUST ENTER A NUMBER" 
else
if lsof -Pi :$sslpt -sTCP:LISTEN -t >/dev/null ; then
echo;echo -e "${lor1}  THE PORT IS ALREADY IN USE"  
else
addgf () {		
echo -e "\n[$namessl] " >> /etc/stunnel/stunnel.conf
echo "connect = 127.0.0.1:$PT" >> /etc/stunnel/stunnel.conf 
echo "accept = $sslpt " >> /etc/stunnel/stunnel.conf 
service stunnel4 restart 1> /dev/null 2> /dev/null
service stunnel restart 1> /dev/null 2> /dev/null
sleep 2
}
fun_bar 'addgf'
echo;echo -e "${lor2} NEW PORT ADDED  $sslpt !${lor7}"
fi;fi;fi
else
echo;echo -e "${lor1} SSL STUNEEL NOT INSTALLED !${lor7}"
fi
fi
if [ "$opci" = "4" ];then
if [ -f /etc/stunnel/stunnel.conf ];then
if netstat -nltp|grep 'stunnel4' > /dev/null; then
service stunnel stop 1> /dev/null 2> /dev/null
service stunnel4 stop 1> /dev/null 2> /dev/null
echo;echo -e "${lor1} SERVICE STOPPED "
else
service stunnel start 1> /dev/null 2> /dev/null
service stunnel4 start 1> /dev/null 2> /dev/null
echo;echo -e "${lor2} SERVICE STARTED "
fi
else
echo;echo -e "${lor1} SSL STUNNEL IS NOT INSTALLED "
fi
fi
espe
;;
8)clear&&clear
echo -e "${lor4}***************************************************${lor7}"
echo -e "${lor2}                      CREDITS "
echo -e "${lor1}===================================================${lor7} "
echo -e "${lor4}$banner ${lor7}"
echo -e "${lor7}      Mini Script Panel created by @KillShito "
echo -e "${lor1}[-]â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”[-]${lor7}"
echo -e "${lor5} SCRIPT DEVELOPER CREDITS:${lor7}@killshito "
echo -e "${lor5} SSH OVER WEBSOCKET CDN CLOUDFLARE:${lor7}@PANCHO7532 "
echo -e "${lor1} PROHIBIDA SU VENTA,SALE FORBIDDEN"
echo
echo -e "${lor3} SI TE VENDIERON ESTE SCRIPT FUISTE ESTAFADO "
echo -e "${lor3} IF THEY SOLD YOU THIS SCRIPT YOU WERE SCAMMED "
espe
;;
9)exit;;
esac 
done