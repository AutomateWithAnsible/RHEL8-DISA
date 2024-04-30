#!/bin/bash
##################### MEDIUM FINDINGS #####################
# Configure GnuTLS library to use DoD-approved TLS Encryption
CONF_FILE=/etc/crypto-policies/back-ends/gnutls.config
correct_value='+VERS-ALL:-VERS-DTLS0.9:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0'
grep -q ${correct_value} ${CONF_FILE}
if [[ $? -ne 0 ]]; then
    # We need to get the existing value, using PCRE to maintain same regex
    existing_value=$(grep -Po '(\+VERS-ALL(?::-VERS-[A-Z]+\d\.\d)+)' ${CONF_FILE})
    if [[ ! -z ${existing_value} ]]; then
        # replace existing_value with correct_value
        sed -i "s/${existing_value}/${correct_value}/g" ${CONF_FILE}
    else
        # ***NOTE*** #
        # This probably means this file is not here or it's been modified
        # unintentionally.
        # ********** #
        # echo correct_value to end
        echo ${correct_value} >> ${CONF_FILE}
    fi
fi
# Build and Test AIDE Database
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if ! rpm -q --quiet "aide" ; then
    yum install -y "aide"
fi
/usr/sbin/aide --init
/bin/cp -p /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Configure AIDE to Verify the Audit Tools
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if ! rpm -q --quiet "aide" ; then
    yum install -y "aide"
fi
if grep -i '^.*/usr/sbin/auditctl.*$' /etc/aide.conf; then
sed -i "s#.*/usr/sbin/auditctl.*#/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
else
echo "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
fi
if grep -i '^.*/usr/sbin/auditd.*$' /etc/aide.conf; then
sed -i "s#.*/usr/sbin/auditd.*#/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
else
echo "/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
fi
if grep -i '^.*/usr/sbin/ausearch.*$' /etc/aide.conf; then
sed -i "s#.*/usr/sbin/ausearch.*#/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
else
echo "/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
fi
if grep -i '^.*/usr/sbin/aureport.*$' /etc/aide.conf; then
sed -i "s#.*/usr/sbin/aureport.*#/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
else
echo "/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
fi
if grep -i '^.*/usr/sbin/autrace.*$' /etc/aide.conf; then
sed -i "s#.*/usr/sbin/autrace.*#/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
else
echo "/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
fi
if grep -i '^.*/usr/sbin/augenrules.*$' /etc/aide.conf; then
sed -i "s#.*/usr/sbin/augenrules.*#/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
else
echo "/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
fi
if grep -i '^.*/usr/sbin/rsyslogd.*$' /etc/aide.conf; then
sed -i "s#.*/usr/sbin/rsyslogd.*#/usr/sbin/rsyslogd p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
else
echo "/usr/sbin/rsyslogd p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Configure Notification of Post-AIDE Scan Details
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if ! rpm -q --quiet "aide" ; then
    yum install -y "aide"
fi
var_aide_scan_notification_email='root@localhost'
CRONTAB=/etc/crontab
CRONDIRS='/etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly'
if [ -f /etc/crontab ]; then
	CRONTAB_EXIST=/etc/crontab
fi
if [ -f /var/spool/cron/root ]; then
	VARSPOOL=/var/spool/cron/root
fi
if ! grep -qR '^.*/usr/sbin/aide\s*\-\-check.*|.*\/bin\/mail\s*-s\s*".*"\s*.*@.*$' $CRONTAB_EXIST $VARSPOOL $CRONDIRS; then
	echo "0 5 * * * root /usr/sbin/aide  --check | /bin/mail -s \"\$(hostname) - AIDE Integrity Check\" $var_aide_scan_notification_email" >> $CRONTAB
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Configure SSH to use System Crypto Policy
SSH_CONF="/etc/sysconfig/sshd"
sed -i "/^\s*CRYPTO_POLICY.*$/Id" $SSH_CONF
# Configure SSH Server to Use FIPS 140-2 Validated Ciphers: opensshserver.config
sshd_approved_ciphers='aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com'
CONF_FILE=/etc/crypto-policies/back-ends/opensshserver.config
correct_value="-oCiphers=${sshd_approved_ciphers}"
# Test if file exists
test -f ${CONF_FILE} || touch ${CONF_FILE}
# Ensure CRYPTO_POLICY is not commented out
sed -i 's/#CRYPTO_POLICY=/CRYPTO_POLICY=/' ${CONF_FILE}
grep -q "'${correct_value}'" ${CONF_FILE}
if [[ $? -ne 0 ]]; then
    # We need to get the existing value, using PCRE to maintain same regex
    existing_value=$(grep -Po '(-oCiphers=\S+)' ${CONF_FILE})
    if [[ ! -z ${existing_value} ]]; then
        # replace existing_value with correct_value
        sed -i "s/${existing_value}/${correct_value}/g" ${CONF_FILE}
    else
        # ***NOTE*** #
        # This probably means this file is not here or it's been modified
        # unintentionally.
        # ********** #
        # echo correct_value to end
        echo "CRYPTO_POLICY='${correct_value}'" >> ${CONF_FILE}
    fi
fi
# Configure SSH Client to Use FIPS 140-2 Validated MACs: openssh.config
sshd_approved_macs='hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com'
if [ -e "/etc/crypto-policies/back-ends/openssh.config" ] ; then
    LC_ALL=C sed -i "/^.*MACs\s\+/d" "/etc/crypto-policies/back-ends/openssh.config"
else
    touch "/etc/crypto-policies/back-ends/openssh.config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/crypto-policies/back-ends/openssh.config"
cp "/etc/crypto-policies/back-ends/openssh.config" "/etc/crypto-policies/back-ends/openssh.config.bak"
# Insert at the end of the file
printf '%s\n' "MACs ${sshd_approved_macs}" >> "/etc/crypto-policies/back-ends/openssh.config"
# Clean up after ourselves.
rm "/etc/crypto-policies/back-ends/openssh.config.bak"
# Configure SSH Server to Use FIPS 140-2 Validated MACs: opensshserver.config
sshd_approved_macs='hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com'
CONF_FILE=/etc/crypto-policies/back-ends/opensshserver.config
correct_value="-oMACs=${sshd_approved_macs}"
# Test if file exists
test -f ${CONF_FILE} || touch ${CONF_FILE}
# Ensure CRYPTO_POLICY is not commented out
sed -i 's/#CRYPTO_POLICY=/CRYPTO_POLICY=/' ${CONF_FILE}
grep -q "'${correct_value}'" ${CONF_FILE}
if [[ $? -ne 0 ]]; then
    # We need to get the existing value, using PCRE to maintain same regex
    existing_value=$(grep -Po '(-oMACs=\S+)' ${CONF_FILE})
    if [[ ! -z ${existing_value} ]]; then
        # replace existing_value with correct_value
        sed -i "s/${existing_value}/${correct_value}/g" ${CONF_FILE}
    else
        # ***NOTE*** #
        # This probably means this file is not here or it's been modified
        # unintentionally.
        # ********** #
        # echo correct_value to end
        echo "CRYPTO_POLICY='${correct_value}'" >> ${CONF_FILE}
    fi
fi
# Install McAfee Endpoint Security for Linux (ENSL)
sudo yum install McAfeeTP -y
# Uninstall tuned Package
sudo yum erase tuned -y
# Ensure Software Patches Installed
sudo yum update -y
# Ensure gpgcheck Enabled for Local Packages
if rpm --quiet -q yum; then
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^localpkg_gpgcheck")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "1"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^localpkg_gpgcheck\\>" "/etc/yum.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^localpkg_gpgcheck\\>.*/$escaped_formatted_output/gi" "/etc/yum.conf"
else
    if [[ -s "/etc/yum.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/yum.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/yum.conf"
    fi
    cce="CCE-80791-7"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/yum.conf" >> "/etc/yum.conf"
    printf '%s\n' "$formatted_output" >> "/etc/yum.conf"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
################### System needs to now be rebooted in order for the FIPS remediation to take effect!! ###################