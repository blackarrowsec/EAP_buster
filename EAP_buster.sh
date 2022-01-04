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
#
# Style Guide
# https://google.github.io/styleguide/shellguide.html

# TODO
#
# - List dependencies
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

readonly EAP_METHOD_LIST=(
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
readonly EAP_ATTRIBUTES=(
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
function print_supported()
{
    echo -e "\r\033[K\033[0;32msupported\033[0m      =>  ${1}"
}

# colored output for EAP methods that are not supported
function print_not_supported()
{
    echo -e "\r\033[K\033[0;31mnot supported\033[0m  =>  ${1}"
}

# BlackArrow banner
function print_banner()
{
    echo -e "\nEAP_buster by BlackArrow [https://github.com/blackarrowsec/EAP_buster]\n"
}

print_banner

# warning about using legitimate EAP identities
function print_identities_warning()
{
    echo -e '\033[1;33mWARNING\033[0m\nYou need to use legitimate EAP identities in order to start the 802.1X authentication process and get reliable results (EAP identites can be collected using sniffing tools such as crEAP, just make sure you use a real identity and not an anonymous one => https://github.com/Snizz/crEAP)\n' >&2
}

print_identities_warning

# checking user permissions
if [ "${USER}" != 'root' ]
then
    echo -e "\033[0;31mPERMISSIONS ERROR\033[0m\nYou need to be root to run ${0}, wpa_supplicant has to be started and stopped several times during execution\n" >&2
    exit 1
fi

# checking number of arguments
if [ ${#} -ne 3 ]
then
    echo -e "\033[0;31mSYNTAX ERROR\033[0m\n${0} <EAP_ESSID> <EAP_identity> <wireless_interface>\n" >&2
    exit 1
fi

readonly EAP_ESSID="${1}"
readonly EAP_IDENTITY="${2}"
readonly WIRELESS_INTERFACE="${3}"
readonly EAP_BUSTER_DIR="$(dirname "${0}" | xargs --delimiter='\n' realpath)"
readonly EAP_CONFIG_DIR="${EAP_BUSTER_DIR}/EAP_config"
readonly EAP_LOG_DIR="${EAP_BUSTER_DIR}/${EAP_ESSID}"
readonly MAC_CHANGE='CHANGE'
readonly MAC_RESTORE='RESTORE'

# checking WIRELESS_INTERFACE existence and saving original MAC address
if ! iw "${WIRELESS_INTERFACE}" info &> '/dev/null'
then
    echo -e "\033[0;31mINPUT ERROR\033[0m\n3rd argument "'"'"${WIRELESS_INTERFACE}"'"'" is not a valid wireless interface\n" >&2
    exit 1
else
    readonly WIRELESS_INTERFACE_MAC="$(iw "${WIRELESS_INTERFACE}" info | grep 'addr' | cut --delimiter=' ' --fields='2')"
fi

# checking EAP_BUSTER_DIR permissions
if [ ! -r "${EAP_BUSTER_DIR}" ] || [ ! -w "${EAP_BUSTER_DIR}" ]
then
    echo -e "\033[0;31mPERMISSIONS ERROR\033[0m\nYou need read and write permissions in ${EAP_BUSTER_DIR}\n" >&2
    exit 1
fi

# checking EAP_CONFIG_DIR permissions
if [ ! -r "${EAP_CONFIG_DIR}" ]
then
    echo -e "\033[0;31mPERMISSIONS ERROR\033[0m\nYou need read permissions in ${EAP_CONFIG_DIR} to access configuration files\n" >&2
    exit 1
fi

# checking EAP_LOG_DIR permissions (and creation if needed)
if [ ! -d "${EAP_LOG_DIR}" ]
then
    mkdir "${EAP_LOG_DIR}"
elif [ ! -r "${EAP_LOG_DIR}" ] || [ ! -w "${EAP_LOG_DIR}" ]
then
    echo -e "\033[0;31mPERMISSIONS ERROR\033[0m\nYou need read and write permissions in ${EAP_LOG_DIR} to create and access wpa_supplicant logs\n" >&2
    exit 1
fi

# change to random or restore MAC address to avoid network bans
function modify_mac_address()
{
    ip link set dev "${WIRELESS_INTERFACE}" down
    if [ "${1}" == "${MAC_CHANGE}" ]
    then
        urandom_6="$(xxd -plain -len '6' '/dev/urandom')"
        wireless_interface_mac_new="${urandom_6:0:1}0:${urandom_6:2:2}:${urandom_6:4:2}:${urandom_6:6:2}:${urandom_6:8:2}:${urandom_6:10:2}"
        ip link set dev "${WIRELESS_INTERFACE}" address "${wireless_interface_mac_new}"
    elif [ "${1}" == "${MAC_RESTORE}" ]
    then
        ip link set dev "${WIRELESS_INTERFACE}" address "${WIRELESS_INTERFACE_MAC}"
    fi
    ip link set dev "${WIRELESS_INTERFACE}" up
}

# values needed to build wpa_supplicant configuration files
readonly EAP_VALUES=(
"${EAP_ESSID}"
"${EAP_IDENTITY}"
"${EAP_BUSTER_DIR}/user.pem"
"${EAP_BUSTER_DIR}/user.key"
'whatever'
"${EAP_BUSTER_DIR}/user.pem"
"${EAP_BUSTER_DIR}/user.key"
'whatever'
)

# network interface mode configuration
ip link set dev "${WIRELESS_INTERFACE}" down
iw dev "${WIRELESS_INTERFACE}" set type managed
ip link set dev "${WIRELESS_INTERFACE}" up

# certificate + key generation using the specified identity and ESSID
openssl req -x509 -newkey 'rsa:4096' -keyout "${EAP_BUSTER_DIR}/user.key" -out "${EAP_BUSTER_DIR}/user.pem" -days '365' -passout 'pass:whatever' -subj "/CN=${EAP_IDENTITY}/O=${EAP_ESSID}" &> '/dev/null'

# stop wpa_supplicant before starting
killall --quiet 'wpa_supplicant'

# main loop between EAP methods
for eap_method in "${EAP_METHOD_LIST[@]}"
do
    eap_config_file="${EAP_CONFIG_DIR}/${eap_method}.conf"
    if [ -f "${eap_config_file}" ] && [ -r "${eap_config_file}" ] && [ -w "${eap_config_file}" ]
    then
        eap_log_file="${EAP_LOG_DIR}/${EAP_ESSID}_${eap_method}.log"
        echo -n '' > "${eap_log_file}"
        echo -n "checking ${eap_method} support ..."
        
        # wpa_supplicant attributes configuration
        for eap_tuple in $(echo "$(( "${#EAP_ATTRIBUTES[@]}" - 1 ))" | xargs seq '0')
        do
            sed --in-place "s|${EAP_ATTRIBUTES[${eap_tuple}]}=.*|${EAP_ATTRIBUTES[${eap_tuple}]}=\"${EAP_VALUES[${eap_tuple}]}\"|g" "${eap_config_file}"
        done
        
        # MAC address change and wpa_supplicant execution
        modify_mac_address "${MAC_CHANGE}"
        timeout '10' wpa_supplicant -d -K -D 'nl80211' -i "${WIRELESS_INTERFACE}" -c "${eap_config_file}" -f "${eap_log_file}"
        sleep '5'
        
        # check log file to identify supported EAP methods
        if grep --quiet 'EAP: Status notification: accept proposed method' "${eap_log_file}"
        then
            if grep --quiet 'TLS: Phase 2 Request: Nak' "${eap_log_file}"
            then
                if grep --quiet 'Selected Phase 2' "${eap_log_file}"
                then
                    print_supported "${eap_method}"
                else
                    print_not_supported "${eap_method}"
                fi
            
            # no 'Phase 2 Nak' at this point means that either the phase 2 has been selected or there is no phase 2 at all
            else
                print_supported "${eap_method}"
            fi
        else
            print_not_supported "${eap_method}"
        fi
    fi
done

# MAC address restoration
modify_mac_address "${MAC_RESTORE}"
echo ''

exit 0
