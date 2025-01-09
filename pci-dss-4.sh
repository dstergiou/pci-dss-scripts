#!/bin/bash

# TTS PCI DSS Linux host information gather
# Dimitrios Stergiou <dimitrios.stergiou@taptapsend.com>
#
# Description
# -----------
# Auditing tool to gather information for PCI DSS 4.0 Compliance
#
# Source: Vanta
# URL: https://app.eu.vanta.com/documents/system-configuration-unix-linux-sample
#
# Requirement list
# ----------------
# 1) Host name
# 2) OS name and version
# 3) IP address
# 4) List of all local user accounts (PCI 2.2.2; 8.1; 8.2.2)
# 5) List of all administrator accounts
# 6) Last security patch installed (PCI 6.2)
# 7) List of all processes/services running (PCI 2.x; 5.x; 11.5)
# 8) List of listening and established connections
# 9) Local password configuration settings that show:
# 9.1) Minimum password length of at least twelve characters where technically possible and 8 where not (PCI 8.3.6)
# 9.2) Passwords containing both numeric and alphabetic characters (PCI 8.3.6)
# 9.3) Passwords containing both numeric and alphabetic characters if only username and password are used (PCI 8.3.9)
# 9.4) Passwords history of at least 4 (PCI 8.3.7).
# 9.5) Lock out after not more than six attempts (PCI 8.3.4).
# 9.6) Lockout duration of 30 minutes or until administrator enables the user ID (PCI 8.3.4).
# 9.7) Re-authentication for idle session of more than 15 minutes (PCI 8.2.8).
# 10) Audit log settings (PCI 10.2).
# 11) NTP settings (PCI 10.4).
# 12) Vendor security patch list. This list should include a link to the vendor’s website which shows the latest patches available and should reconcile with point #5 above.
# 13) Specify the name of the service(s) running for the anti-virus solution. These services must be found in the output of point #6 above.
# 14) Specify the name of the service(s) running for the File Integrity Monitoring (FIM) solution. These services must be found in the output of point #6 above

# Configuration
#--------------
SITENAME="TTS"

# Variables
#----------
DATE=`date +%Y.%m.%d-%H:%M:%S`
USERDIR=$(eval echo ~${SUDO_USER})

# Report directory creation
rootdir=$USERDIR/PCI_DSS_REPORT
OUTPUT_DIR=$DATE-$SITENAME-$HOSTNAME
REPORT="$rootdir/$OUTPUT_DIR-report.txt"

if [ ! -d "$rootdir" ]; then
  mkdir "$rootdir"
fi

touch $REPORT

# 1) Hostname
get_hostname() {
  echo "Grabbing hostname"
  hostname=$(hostname)
  echo "1) Hostname" >> $REPORT
  echo $hostname >> $REPORT
  echo "" >> $REPORT
}

# 2) OS name and version
get_os_info() {
    echo "Grabbing OS name and version"
    os_info=$(lsb_release -d | awk -F'\t' '{print $2}')
    echo "2) OS name and version" >> $REPORT
    echo $os_info >> $REPORT
    echo "" >> $REPORT
}

# 3) IP address
get_ip_address() {
  echo "Grabbing IP address"
  ip_address=$(hostname -I | awk '{print $1}')
  echo "3) IP Address" >> $REPORT
  echo $ip_address >> $REPORT
  echo "" >> $REPORT
}

# 4) List of all local user accounts
get_local_users() {
    echo "Grabbing list of local user accounts"
    local_users=$(awk -F: '{ if ($3 >= 1000 && $3 < 65534) print $1 }' /etc/passwd)
    echo "4) Local users" >> $REPORT
    echo $local_users >> $REPORT
    echo "" >> $REPORT
}

# 5) List of all administrator accounts
get_admin_users() {
    echo "Grabbing list of administrator accounts"
    admin_users=$(getent group sudo | awk -F: '{print $4}')
    echo "5) Admin users" >> $REPORT
    echo $admin_users >> $REPORT
    echo "" >> $REPORT
}

# 6) Last security patch installed
get_latest_patches() {
    echo "Grabbing last patches installed"
    last_patch=$(grep "installed" /var/log/dpkg.log /var/log/dpkg.log.1 | grep -v "not-installed" | grep -v "half-installed" | sort -rn)
    echo "6) Last 25 patches installed" >> $REPORT
    echo "$last_patch" >> $REPORT
    echo "" >> $REPORT

}

# 7) List of all processes/services running
get_running_processes() {
    echo "Grabbing list of all processes/services running"
    running_processes=$(ps aux)
    echo "7) Running processes" >> $REPORT
    echo "$running_processes" >> $REPORT
    echo "" >> $REPORT
}

# 8) List of listening and established connections
get_network_connections() {
    echo "Grabbing list of listening and established connections"
    network_connections=$(ss -tuln)
    echo "8) Established connections" >> $REPORT
    echo "$network_connections" >> $REPORT
    echo "" >> $REPORT
}

# 9) Password configuration
get_password_configuration() {
    echo "Grabbing local password configuration settings"
    echo "9) Password configuration" >> $REPORT

    min_length=$(grep -E 'PASS_MIN_LEN' /etc/login.defs | awk '{print $2}')
    echo "Minimum password length: $min_length" >> $REPORT

    pass_complexity=$(grep -E 'pam_unix.so' /etc/pam.d/common-password | grep -o 'minlen=[0-9]*' | cut -d'=' -f2)
    echo "Password complexity (numeric and alphabetic): $pass_complexity" >> $REPORT

    pass_history=$(grep -E 'remember' /etc/pam.d/common-password | awk '{print $3}')
    echo "Password history: $pass_history" >> $REPORT

    lock_attempts=$(grep -E 'maxretry' /etc/pam.d/common-auth | awk '{print $3}')
    echo "Lock out after attempts: $lock_attempts" >> $REPORT

    lock_duration=$(grep -E 'faildelay' /etc/pam.d/common-auth | awk '{print $3}')
    echo "Lockout duration: $lock_duration" >> $REPORT

    idle_reauth=$(grep -E 'idle' /etc/pam.d/common-auth | awk '{print $2}')
    echo "Re-authentication for idle session: $idle_reauth" >> $REPORT

    ssh_password_auth=$(grep -E '^PasswordAuthentication' /etc/ssh/sshd_config)
    echo "SSHD password authentication: $ssh_password_auth" >> $REPORT

    echo "" >> $REPORT
}

# 10) Audit log settings
get_audit_log_settings() {
    echo "Grabbing audit log settings"
    echo "10) Audit log settings" >> $REPORT

    datadog_status=$(systemctl is-active datadog-agent)
    echo "Datadog agent service status: $datadog_status" >> $REPORT

    datadog_config_file=$(grep -E 'logs_enabled' /etc/datadog-agent/datadog.yaml)
    echo "Datadog logs: $datadog_config_file" >> $REPORT

    datadog_version=$(datadog-agent version)
    echo "Datadog agent version: $datadog_version" >> $REPORT

    echo "" >> $REPORT
}

# 11) NTP settings
get_ntp_settings() {
    echo "Grabbing NTP settings"
    echo "11) NTP settings" >> $REPORT

    chrony_status=$(systemctl is-active chrony)
    echo "Chrony service status: $chrony_status" >> $REPORT

    chrony_sources=$(chronyc sources -v | grep -E '^\^')
    echo "Chrony NTP sources: $chrony_sources" >> $REPORT

    chrony_sync_status=$(chronyc tracking | grep -E 'Leap|Stratum')
    echo "Chrony synchronization status: $chrony_sync_status" >> $REPORT


    echo "" >> $REPORT
}

# 12) Vendor security patch list.
get_vendor_patch_list() {
    echo "Grabbing vendor security patch list"
    echo "12) Vendor security patches" >> $REPORT
    echo "Vulnerabilities are triaged in Vanta and only selected patches are installed" >> $REPORT
    echo "" >> $REPORT

}

# 13) Antivirus
get_antivirus() {
    echo "Grabbing antivirus"
    echo "13) Antivirus" >> $REPORT
    echo "Implemented on AWS" >> $REPORT
    echo "" >> $REPORT
}

# 14) File Integrity Monitoring
get_file_integrity_monitoring() {
    echo "Grabbing File Integrity Monitoring"
    echo "14) File Integrity Monitoring" >> $REPORT

    aide_installed=$(dpkg-query -s aide &>/dev/null && echo "AIDE is installed")
    echo $aide_installed >> $REPORT

    aide_cron="/etc/cron.daily/aide"
    aide_config="/etc/aide/aide.conf"
    aide_db="/var/lib/aide/aide.db"

    if [ -e $aide_cron ]; then
        echo "AIDE running: $aide_cron" >> $REPORT
    fi

    if [ -e $aide_config ]; then
        echo "AIDE config: $aide_config" >> $REPORT
    fi

    if [ -e $aide_db ]; then
        echo "AIDE DB: $aide_db" >> $REPORT
    fi

    echo "" >> $REPORT

}

# Main script
get_hostname
get_os_info
get_ip_address
get_local_users
get_admin_users
get_latest_patches
get_running_processes
get_network_connections
get_password_configuration
get_audit_log_settings
get_ntp_settings
get_vendor_patch_list
get_antivirus
get_file_integrity_monitoring
