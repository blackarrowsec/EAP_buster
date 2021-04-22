#!/usr/bin/env bash

# EAP_buster by BlackArrow [https://github.com/blackarrowsec/EAP_buster]
#
# Description
# EAP_buster is a simple bash script that lists what EAP methods are supported
# by the RADIUS server behind a WPA-Enterprise access point. In order to achieve
# this, it makes use of several wpa_supplicant configuration files along with
# WPA-Enterprise identities, which can be grabbed with some passive sniffing.
#
# Author
# Miguel Amat (t.me/m_amatb) from BlackArrow
#
# Details
# https://github.com/blackarrowsec/EAP_buster/README.md
#
# Web
# [www.blackarrow.net] - [www.tarlogic.com]

# TODO
#
# - Parse arguments using getops instead of manually
# - Restore wpa_supplicant original status after execution
# - Be able to grab various EAP identities from a file to avoid network bans
# - Thoroughly test the existent configuration files
# - Find pending configuration files for weird EAP methods
# - Detect network bans and set incremental timers
# - Group tries by phase1 methods to discard all not supported phase2 variants
# - Add support for hidden networks
# - Handle SIGINT to restore MAC address on exit
# - Grab EAP identities using tcpdump

EAP_method_list=(
'EAP-TLS'
'EAP-PEAP_MSCHAPV2'
'EAP-PEAP_TLS'
'EAP-PEAP_GTC'
'EAP-PEAP_OTP'
'EAP-PEAP_MD5-Challenge'
'EAP-TTLS_EAP-MD5-Challenge'
'EAP-TTLS_EAP-GTC'
'EAP-TTLS_EAP-OTP'
'EAP-TTLS_EAP-MSCHAPV2'
'EAP-TTLS_EAP-TLS'
'EAP-TTLS_MSCHAPV2'
'EAP-TTLS_MSCHAP'
'EAP-TTLS_PAP'
'EAP-TTLS_CHAP'
'EAP-SIM'
'EAP_AKA'
'EAP-PSK'
'EAP-PAX'
'EAP-SAKE'
'EAP-IKEv2'
'EAP-GPSK'
'LEAP'
'EAP-FAST_MSCHAPV2'
'EAP-FAST_GTC'
'EAP-FAST_OTP'
)

# attributes needed to build wpa_supplicant configuration files
EAP_attributes=(
'ssid'
'identity'
'client_cert'
'private_key'
'key_passwd'
'client_cert2'
'private_key2'
'key2_passwd'
)

# colored output for EAP methods that are supported
print_supported()
{
    echo -e "\r\033[K\033[0;32msupported\033[0m      =>  ${1}"
}

# colored output for EAP methods that are not supported
print_not_supported()
{
    echo -e "\r\033[K\033[0;31mnot supported\033[0m  =>  ${1}"
}

# BlackArrow banner
print_banner()
{
    echo -e "\nEAP_buster by BlackArrow [https://github.com/blackarrowsec/EAP_buster]\n"
}

print_banner

# warning about using legitimate EAP identities
print_identities_warning()
{
    echo -e '\033[1;33mWARNING\033[0m\nYou need to use legitimate EAP identities in order to start the 802.1X authentication process and get reliable results (EAP identites can be collected using sniffing tools such as crEAP, just make sure you use a real identity and not an anonymous one => https://github.com/Snizz/crEAP)\n'
}

print_identities_warning

# checking user permissions
if [ "${USER}" != 'root' ]
then
    echo -e "\033[0;31mPERMISSIONS ERROR\033[0m\nYou need to be root to run ${0}, wpa_supplicant has to be started and stopped several times during execution\n"
    exit 1
fi

# checking number of arguments
if [ "${#}" != '3' ]
then
    echo -e "\033[0;31mSYNTAX ERROR\033[0m\n${0} <EAP_ESSID> <EAP_identity> <wireless_interface>\n"
    exit 1
fi

EAP_ESSID="${1}"
EAP_identity="${2}"
wireless_interface="${3}"
EAP_buster_dir="$(readlink -f $(dirname "${0}"))"
EAP_config_dir="${EAP_buster_dir}/EAP_config"
EAP_log_dir="${EAP_buster_dir}/${EAP_ESSID}"

# checking wireless_interface existence and saving original mac address
if ! iw "${wireless_interface}" 'info' &> '/dev/null'
then
    echo -e "\033[0;31mINPUT ERROR\033[0m\n3rd argument "'"'"${wireless_interface}"'"'" is not a valid wireless interface\n"
    exit 1
else
    wireless_interface_mac="$(iw "${wireless_interface}" 'info' | grep 'addr' | cut --delimiter=' ' --fields='2')"
fi

# checking EAP_buster_dir permissions
if [ ! -r "${EAP_buster_dir}" ] || [ ! -w "${EAP_buster_dir}" ]
then
    echo -e "\033[0;31mPERMISSIONS ERROR\033[0m\nYou need read and write permissions in ${EAP_buster_dir}\n"
    exit 1
fi

# checking EAP_config_dir permissions
if [ ! -r "${EAP_config_dir}" ]
then
    echo -e "\033[0;31mPERMISSIONS ERROR\033[0m\nYou need read permissions in ${EAP_config_dir} to access configuration files\n"
    exit 1
fi

# checking EAP_log_dir permissions (and creation if needed)
if [ ! -d "${EAP_log_dir}" ]
then
    mkdir "${EAP_log_dir}"
elif [ ! -r "${EAP_log_dir}" ] || [ ! -w "${EAP_log_dir}" ]
then
    echo -e "\033[0;31mPERMISSIONS ERROR\033[0m\nYou need read and write permissions in ${EAP_log_dir} to create and access wpa_supplicant logs\n"
    exit 1
fi

# change to random or restore mac address to avoid network bans
modify_mac_address()
{
    ifconfig "${wireless_interface}" 'down'
    if [ "${1}" == 'change' ]
    then
        urandom_6="$(xxd -plain -len '6' '/dev/urandom')"
        wireless_interface_mac_new="${urandom_6:0:1}0:${urandom_6:2:2}:${urandom_6:4:2}:${urandom_6:6:2}:${urandom_6:8:2}:${urandom_6:10:2}"
        ifconfig "${wireless_interface}" 'hw' 'ether' "${wireless_interface_mac_new}"
    elif [ "${1}" == 'restore' ]
    then
        ifconfig "${wireless_interface}" 'hw' 'ether' "${wireless_interface_mac}"
    fi
    ifconfig "${wireless_interface}" 'up'
}

# values needed to build wpa_supplicant configuration files
EAP_values=(
"${EAP_ESSID}"
"${EAP_identity}"
"${EAP_buster_dir}/user.pem"
"${EAP_buster_dir}/user.key"
'whatever'
"${EAP_buster_dir}/user.pem"
"${EAP_buster_dir}/user.key"
'whatever'
)

# network interface mode configuration
ifconfig "${wireless_interface}" 'down'
iw dev "${wireless_interface}" 'set' 'type' 'managed'
ifconfig "${wireless_interface}" 'up'

# certificate + key generation using the specified identity and ESSID
openssl 'req' -x509 -newkey 'rsa:4096' -keyout "${EAP_buster_dir}/user.key" -out "${EAP_buster_dir}/user.pem" -days '365' -passout 'pass:whatever' -subj "/CN=${EAP_identity}/O=${EAP_ESSID}" &> '/dev/null'

# stop wpa_supplicant before starting
killall --quiet 'wpa_supplicant'

# main loop between EAP methods
for EAP_method in "${EAP_method_list[@]}"
do
    EAP_config_file="${EAP_config_dir}/${EAP_method}.conf"
    if [ -f "${EAP_config_file}" ] && [ -r "${EAP_config_file}" ] && [ -w "${EAP_config_file}" ]
    then
        EAP_log_file="${EAP_log_dir}/${EAP_ESSID}_${EAP_method}.log"
        echo '' > "${EAP_log_file}"
        echo -n "checking ${EAP_method} support ..."
        
        # wpa_supplicant attributes configuration
        for EAP_tuple in $(seq '0' "$(("${#EAP_attributes[@]}" - "1"))")
        do
            sed --in-place "s|${EAP_attributes[${EAP_tuple}]}=.*|${EAP_attributes[${EAP_tuple}]}=\"${EAP_values[${EAP_tuple}]}\"|g" "${EAP_config_file}"
        done
        
        # mac address change and wpa_supplicant execution
        modify_mac_address 'change'
        timeout '10' wpa_supplicant -d -K -D 'nl80211' -i "${wireless_interface}" -c "${EAP_config_file}" -f "${EAP_log_file}"
        sleep '5'
        
        # check log file to identify supported EAP methods
        if grep --quiet 'EAP: Status notification: accept proposed method' "${EAP_log_file}"
        then
            if grep --quiet 'TLS: Phase 2 Request: Nak' "${EAP_log_file}"
            then
                if grep --quiet 'Selected Phase 2' "${EAP_log_file}"
                then
                    print_supported "${EAP_method}"
                else
                    print_not_supported "${EAP_method}"
                fi
            
            # no 'Phase 2 Nak' at this point means that either the phase 2 has been selected or there is no phase 2 at all
            else
                print_supported "${EAP_method}"
            fi
        else
            print_not_supported "${EAP_method}"
        fi
    fi
done

echo ''
modify_mac_address 'restore'

exit 0
