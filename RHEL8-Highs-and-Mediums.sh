#!/bin/bash
echo "################## Disable Ctrl-Alt-Del Burst Action"
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { rpm --quiet -q systemd; }; then
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^CtrlAltDelBurstAction=")
printf -v formatted_output "%s=%s" "$stripped_key" "none"
if LC_ALL=C grep -q -m 1 -i -e "^CtrlAltDelBurstAction=\\>" "/etc/systemd/system.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^CtrlAltDelBurstAction=\\>.*/$escaped_formatted_output/gi" "/etc/systemd/system.conf"
else
    if [[ -s "/etc/systemd/system.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/systemd/system.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/systemd/system.conf"
    fi
    cce="CCE-80784-2"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/systemd/system.conf" >> "/etc/systemd/system.conf"
    printf '%s\n' "$formatted_output" >> "/etc/systemd/system.conf"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Disable Ctrl-Alt-Del Reboot Activation"
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
systemctl disable --now ctrl-alt-del.target
systemctl mask --now ctrl-alt-del.target
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Ensure SELinux State is Enforcing"
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
var_selinux_state='enforcing'
if [ -e "/etc/selinux/config" ] ; then

    LC_ALL=C sed -i "/^SELINUX=/Id" "/etc/selinux/config"
else
    touch "/etc/selinux/config"
fi
sed -i -e '$a\' "/etc/selinux/config"
cp "/etc/selinux/config" "/etc/selinux/config.bak"
printf '%s\n' "SELINUX=$var_selinux_state" >> "/etc/selinux/config"
rm "/etc/selinux/config.bak"
fixfiles onboot
fixfiles -f relabel
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Account Lockouts Must Be Logged"
if grep -qP "^ID=[\"']?rhel[\"']?$" "/etc/os-release" && { real="$(grep -P "^VERSION_ID=[\"']?[\w.]+[\"']?$" /etc/os-release | sed "s/^VERSION_ID=[\"']\?\([^\"']\+\)[\"']\?$/\1/")"; expected="8.2"; printf "%s\n%s" "$expected" "$real" | sort -VC; }; then
if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock
authselect apply-changes -b
else
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
for pam_file in "${AUTH_FILES[@]}"
do
    if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
        sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
        sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
        sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
    fi
    sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
done
fi
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f $FAILLOCK_CONF ]; then
    regex="^\s*audit"
    line="audit"
    if ! grep -q $regex $FAILLOCK_CONF; then
        echo $line >> $FAILLOCK_CONF
    fi
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -e "$pam_file" ] ; then
            PAM_FILE_PATH="$pam_file"
            if [ -f /usr/bin/authselect ]; then
                if ! authselect check; then
                echo "
                authselect integrity check failed. Remediation aborted!
                This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                It is not recommended to manually edit the PAM files when authselect tool is available.
                In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                exit 1
                fi
                CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                    ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                    authselect create-profile hardening -b $CURRENT_PROFILE
                    CURRENT_PROFILE="custom/hardening"
                    authselect apply-changes -b --backup=before-hardening-custom-profile
                    authselect select $CURRENT_PROFILE
                    for feature in $ENABLED_FEATURES; do
                        authselect enable-feature $feature;
                    done
                    authselect apply-changes -b --backup=after-hardening-custom-profile
                fi
                PAM_FILE_NAME=$(basename "$pam_file")
                PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"
                authselect apply-changes -b
            fi
        if grep -qP '^\s*auth\s.*\bpam_faillock.so\s.*\baudit\b' "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks 's/(.*auth.*pam_faillock.so.*)\baudit\b=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
        fi
            if [ -f /usr/bin/authselect ]; then
                authselect apply-changes -b
            fi
        else
            echo "$pam_file was not found" >&2
        fi
    done
else
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*audit' "$pam_file"; then
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ audit/' "$pam_file"
        fi
    done
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Lock Accounts After Failed Password Attempts"
if rpm --quiet -q pam; then
var_accounts_passwords_pam_faillock_deny='3'
if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock
authselect apply-changes -b
else
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
for pam_file in "${AUTH_FILES[@]}"
do
    if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
        sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
        sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
        sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
    fi
    sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
done
fi
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f $FAILLOCK_CONF ]; then
    regex="^\s*deny\s*="
    line="deny = $var_accounts_passwords_pam_faillock_deny"
    if ! grep -q $regex $FAILLOCK_CONF; then
        echo $line >> $FAILLOCK_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(deny\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_deny"'|g' $FAILLOCK_CONF
    fi
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -e "$pam_file" ] ; then
            PAM_FILE_PATH="$pam_file"
            if [ -f /usr/bin/authselect ]; then
                if ! authselect check; then
                echo "
                authselect integrity check failed. Remediation aborted!
                This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                It is not recommended to manually edit the PAM files when authselect tool is available.
                In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                exit 1
                fi
                CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                    ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                    authselect create-profile hardening -b $CURRENT_PROFILE
                    CURRENT_PROFILE="custom/hardening"
                    authselect apply-changes -b --backup=before-hardening-custom-profile
                    authselect select $CURRENT_PROFILE
                    for feature in $ENABLED_FEATURES; do
                        authselect enable-feature $feature;
                    done
                    authselect apply-changes -b --backup=after-hardening-custom-profile
                fi
                PAM_FILE_NAME=$(basename "$pam_file")
                PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"
                authselect apply-changes -b
            fi
        if grep -qP '^\s*auth\s.*\bpam_faillock.so\s.*\bdeny\b' "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks 's/(.*auth.*pam_faillock.so.*)\bdeny\b=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
        fi
            if [ -f /usr/bin/authselect ]; then
                authselect apply-changes -b
            fi
        else
            echo "$pam_file was not found" >&2
        fi
    done
else
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*deny' "$pam_file"; then
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ deny='"$var_accounts_passwords_pam_faillock_deny"'/' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ deny='"$var_accounts_passwords_pam_faillock_deny"'/' "$pam_file"
        else
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*silent.*\)\('"deny"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_deny"'\3/' "$pam_file"
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"deny"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_deny"'\3/' "$pam_file"
        fi
    done
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Configure the root Account for Failed Password Attempts"
if rpm --quiet -q pam; then
if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock
authselect apply-changes -b
else
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
for pam_file in "${AUTH_FILES[@]}"
do
    if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
        sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
        sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
        sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
    fi
    sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
done
fi
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f $FAILLOCK_CONF ]; then
    regex="^\s*even_deny_root"
    line="even_deny_root"
    if ! grep -q $regex $FAILLOCK_CONF; then
        echo $line >> $FAILLOCK_CONF
    fi
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -e "$pam_file" ] ; then
            PAM_FILE_PATH="$pam_file"
            if [ -f /usr/bin/authselect ]; then
                if ! authselect check; then
                echo "
                authselect integrity check failed. Remediation aborted!
                This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                It is not recommended to manually edit the PAM files when authselect tool is available.
                In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                exit 1
                fi
                CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                    ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                    authselect create-profile hardening -b $CURRENT_PROFILE
                    CURRENT_PROFILE="custom/hardening"
                    authselect apply-changes -b --backup=before-hardening-custom-profile
                    authselect select $CURRENT_PROFILE
                    for feature in $ENABLED_FEATURES; do
                        authselect enable-feature $feature;
                    done
                    authselect apply-changes -b --backup=after-hardening-custom-profile
                fi
                PAM_FILE_NAME=$(basename "$pam_file")
                PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"
                authselect apply-changes -b
            fi
        if grep -qP '^\s*auth\s.*\bpam_faillock.so\s.*\beven_deny_root\b' "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks 's/(.*auth.*pam_faillock.so.*)\beven_deny_root\b=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
        fi
            if [ -f /usr/bin/authselect ]; then
                authselect apply-changes -b
            fi
        else
            echo "$pam_file was not found" >&2
        fi
    done
else
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*even_deny_root' "$pam_file"; then
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ even_deny_root/' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ even_deny_root/' "$pam_file"
        fi
    done
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Lock Accounts Must Persist"
if rpm --quiet -q pam; then
var_accounts_passwords_pam_faillock_dir='/var/log/faillock'
if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock
authselect apply-changes -b
else
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
for pam_file in "${AUTH_FILES[@]}"
do
    if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
        sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
        sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
        sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
    fi
    sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
done
fi
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f $FAILLOCK_CONF ]; then
    regex="^\s*dir\s*="
    line="dir = $var_accounts_passwords_pam_faillock_dir"
    if ! grep -q $regex $FAILLOCK_CONF; then
        echo $line >> $FAILLOCK_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(dir\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_dir"'|g' $FAILLOCK_CONF
    fi
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -e "$pam_file" ] ; then
            PAM_FILE_PATH="$pam_file"
            if [ -f /usr/bin/authselect ]; then
                if ! authselect check; then
                echo "
                authselect integrity check failed. Remediation aborted!
                This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                It is not recommended to manually edit the PAM files when authselect tool is available.
                In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                exit 1
                fi
                CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                    ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                    authselect create-profile hardening -b $CURRENT_PROFILE
                    CURRENT_PROFILE="custom/hardening"
                    authselect apply-changes -b --backup=before-hardening-custom-profile
                    authselect select $CURRENT_PROFILE
                    for feature in $ENABLED_FEATURES; do
                        authselect enable-feature $feature;
                    done
                    authselect apply-changes -b --backup=after-hardening-custom-profile
                fi
                PAM_FILE_NAME=$(basename "$pam_file")
                PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"
                authselect apply-changes -b
            fi
        if grep -qP '^\s*auth\s.*\bpam_faillock.so\s.*\bdir\b' "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks 's/(.*auth.*pam_faillock.so.*)\bdir\b=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
        fi
            if [ -f /usr/bin/authselect ]; then
                authselect apply-changes -b
            fi
        else
            echo "$pam_file was not found" >&2
        fi
    done
else
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*dir' "$pam_file"; then
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ dir='"$var_accounts_passwords_pam_faillock_dir"'/' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ dir='"$var_accounts_passwords_pam_faillock_dir"'/' "$pam_file"
        else
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*silent.*\)\('"dir"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_dir"'\3/' "$pam_file"
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"dir"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_dir"'\3/' "$pam_file"
        fi
    done
fi
if ! rpm -q --quiet "python3-libselinux" ; then
    yum install -y "python3-libselinux"
fi
if ! rpm -q --quiet "python3-policycoreutils" ; then
    yum install -y "python3-policycoreutils"
fi
if ! rpm -q --quiet "policycoreutils-python-utils" ; then
    yum install -y "policycoreutils-python-utils"
fi
mkdir -p "$var_accounts_passwords_pam_faillock_dir"
semanage fcontext -a -t faillog_t "$var_accounts_passwords_pam_faillock_dir(/.*)?"
restorecon -R -v "$var_accounts_passwords_pam_faillock_dir"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Set Interval For Counting Failed Password Attempts"
if rpm --quiet -q pam; then
var_accounts_passwords_pam_faillock_fail_interval='900'
if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock
authselect apply-changes -b
else
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
for pam_file in "${AUTH_FILES[@]}"
do
    if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
        sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
        sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
        sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
    fi
    sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
done
fi
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f $FAILLOCK_CONF ]; then
    regex="^\s*fail_interval\s*="
    line="fail_interval = $var_accounts_passwords_pam_faillock_fail_interval"
    if ! grep -q $regex $FAILLOCK_CONF; then
        echo $line >> $FAILLOCK_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(fail_interval\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_fail_interval"'|g' $FAILLOCK_CONF
    fi
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -e "$pam_file" ] ; then
            PAM_FILE_PATH="$pam_file"
            if [ -f /usr/bin/authselect ]; then
                if ! authselect check; then
                echo "
                authselect integrity check failed. Remediation aborted!
                This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                It is not recommended to manually edit the PAM files when authselect tool is available.
                In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                exit 1
                fi
                CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                    ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                    authselect create-profile hardening -b $CURRENT_PROFILE
                    CURRENT_PROFILE="custom/hardening"
                    authselect apply-changes -b --backup=before-hardening-custom-profile
                    authselect select $CURRENT_PROFILE
                    for feature in $ENABLED_FEATURES; do
                        authselect enable-feature $feature;
                    done
                    authselect apply-changes -b --backup=after-hardening-custom-profile
                fi
                PAM_FILE_NAME=$(basename "$pam_file")
                PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"
                authselect apply-changes -b
            fi
        if grep -qP '^\s*auth\s.*\bpam_faillock.so\s.*\bfail_interval\b' "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks 's/(.*auth.*pam_faillock.so.*)\bfail_interval\b=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
        fi
            if [ -f /usr/bin/authselect ]; then
                authselect apply-changes -b
            fi
        else
            echo "$pam_file was not found" >&2
        fi
    done
else
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*fail_interval' "$pam_file"; then
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ fail_interval='"$var_accounts_passwords_pam_faillock_fail_interval"'/' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ fail_interval='"$var_accounts_passwords_pam_faillock_fail_interval"'/' "$pam_file"
        else
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*silent.*\)\('"fail_interval"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_fail_interval"'\3/' "$pam_file"
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"fail_interval"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_fail_interval"'\3/' "$pam_file"
        fi
    done
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Ensure PAM Enforces Password Requirements - Minimum Digit Characters"
if rpm --quiet -q pam; then
var_password_pam_dcredit='-1'
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^dcredit")
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_dcredit"
if LC_ALL=C grep -q -m 1 -i -e "^dcredit\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^dcredit\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-80653-9"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Ensure PAM Enforces Password Requirements - Minimum Different Characters"
if rpm --quiet -q pam; then
var_password_pam_difok='8'
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^difok")
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_difok"
if LC_ALL=C grep -q -m 1 -i -e "^difok\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^difok\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-80654-7"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Ensure PAM Enforces Password Requirements - Minimum Lowercase Characters"
if rpm --quiet -q pam; then
var_password_pam_lcredit='-1'
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^lcredit")
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_lcredit"
if LC_ALL=C grep -q -m 1 -i -e "^lcredit\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^lcredit\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-80655-4"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Ensure PAM Enforces Password Requirements - Maximum Consecutive Repeating Characters from Same Character Class"
if rpm --quiet -q pam; then
var_password_pam_maxclassrepeat='4'
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^maxclassrepeat")
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_maxclassrepeat"
if LC_ALL=C grep -q -m 1 -i -e "^maxclassrepeat\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^maxclassrepeat\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-81034-1"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Ensure PAM Enforces Password Requirements - Minimum Length"
if rpm --quiet -q pam; then
var_password_pam_minlen='15'
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^minlen")
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_minlen"
if LC_ALL=C grep -q -m 1 -i -e "^minlen\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^minlen\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-80656-2"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Ensure PAM Enforces Password Requirements - Minimum Special Characters"
if rpm --quiet -q pam; then
var_password_pam_ocredit='-1'
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^ocredit")
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_ocredit"
if LC_ALL=C grep -q -m 1 -i -e "^ocredit\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^ocredit\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-80663-8"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Ensure PAM Enforces Password Requirements - Authentication Retry Prompts Permitted Per-Session"
if rpm --quiet -q pam; then
var_password_pam_retry='3'
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^retry")
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_retry"
if LC_ALL=C grep -q -m 1 -i -e "^retry\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^retry\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-80664-6"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi
		if [ -e "/etc/pam.d/password-auth" ] ; then
    PAM_FILE_PATH="/etc/pam.d/password-auth"
    if [ -f /usr/bin/authselect ]; then
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi
        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/password-auth")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"
        authselect apply-changes -b
    fi
if grep -qP '^\s*password\s+'".*"'\s+pam_pwquality.so\s.*\bretry\b' "$PAM_FILE_PATH"; then
    sed -i -E --follow-symlinks 's/(.*password.*'".*"'.*pam_pwquality.so.*)\sretry=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
fi
    if [ -f /usr/bin/authselect ]; then
        authselect apply-changes -b
    fi
else
    echo "/etc/pam.d/password-auth was not found" >&2
fi
		if [ -e "/etc/pam.d/system-auth" ] ; then
    PAM_FILE_PATH="/etc/pam.d/system-auth"
    if [ -f /usr/bin/authselect ]; then
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi
        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/system-auth")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"
        authselect apply-changes -b
    fi
if grep -qP '^\s*password\s+'".*"'\s+pam_pwquality.so\s.*\bretry\b' "$PAM_FILE_PATH"; then
    sed -i -E --follow-symlinks 's/(.*password.*'".*"'.*pam_pwquality.so.*)\sretry=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
fi
    if [ -f /usr/bin/authselect ]; then
        authselect apply-changes -b
    fi
else
    echo "/etc/pam.d/system-auth was not found" >&2
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Ensure PAM Enforces Password Requirements - Minimum Uppercase Characters"
if rpm --quiet -q pam; then
var_password_pam_ucredit='-1'
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^ucredit")
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_ucredit"
if LC_ALL=C grep -q -m 1 -i -e "^ucredit\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^ucredit\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-80665-3"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Install the tmux Package"
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if ! rpm -q --quiet "tmux" ; then
    yum install -y "tmux"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Install the opensc Package For Multifactor Authentication"
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if ! rpm -q --quiet "opensc" ; then
    yum install -y "opensc"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Disable debug-shell SystemD Service"
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" stop 'debug-shell.service'
"$SYSTEMCTL_EXEC" disable 'debug-shell.service'
"$SYSTEMCTL_EXEC" mask 'debug-shell.service'
echo "################## Disable socket activation if we have a unit file for it"
if "$SYSTEMCTL_EXEC" -q list-unit-files debug-shell.socket; then
    "$SYSTEMCTL_EXEC" stop 'debug-shell.socket'
    "$SYSTEMCTL_EXEC" mask 'debug-shell.socket'
fi
"$SYSTEMCTL_EXEC" reset-failed 'debug-shell.service' || true
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Configure Logind to terminate idle sessions after certain time of inactivity"
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { ( grep -qP "^ID=[\"']?rhel[\"']?$" "/etc/os-release" && { real="$(grep -P "^VERSION_ID=[\"']?[\w.]+[\"']?$" /etc/os-release | sed "s/^VERSION_ID=[\"']\?\([^\"']\+\)[\"']\?$/\1/")"; expected="8.7"; printf "%s\n%s" "$expected" "$real" | sort -VC; } && grep -qP "^ID=[\"']?rhel[\"']?$" "/etc/os-release" && { real="$(grep -P "^VERSION_ID=[\"']?[\w.]+[\"']?$" /etc/os-release | sed "s/^VERSION_ID=[\"']\?\([^\"']\+\)[\"']\?$/\1/")"; expected="9.0"; [[ "$real" != "$expected" ]]; } ) || grep -qP "^ID=[\"']?ol[\"']?$" "/etc/os-release" && { real="$(grep -P "^VERSION_ID=[\"']?[\w.]+[\"']?$" /etc/os-release | sed "s/^VERSION_ID=[\"']\?\([^\"']\+\)[\"']\?$/\1/")"; expected="8.7"; printf "%s\n%s" "$expected" "$real" | sort -VC; }; }; then
var_logind_session_timeout='900'
if grep -qzosP '[[:space:]]*\[Login]([^\n\[]*\n+)+?[[:space:]]*StopIdleSessionSec' '/etc/systemd/logind.conf'; then
    sed -i "s/StopIdleSessionSec[^(\n)]*/StopIdleSessionSec=$var_logind_session_timeout/" '/etc/systemd/logind.conf'
elif grep -qs '[[:space:]]*\[Login]' '/etc/systemd/logind.conf'; then
    sed -i "/[[:space:]]*\[Login]/a StopIdleSessionSec=$var_logind_session_timeout" '/etc/systemd/logind.conf'
else
    if test -d "/etc/systemd"; then
        printf '%s\n' '[Login]' "StopIdleSessionSec=$var_logind_session_timeout" >> '/etc/systemd/logind.conf'
    else
        echo "Config file directory '/etc/systemd' doesnt exist, not remediating, assuming non-applicability." >&2
    fi
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Set Password Maximum Age"
if rpm --quiet -q shadow-utils; then
var_accounts_maximum_age_login_defs='60'
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^PASS_MAX_DAYS")
printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_maximum_age_login_defs"
if LC_ALL=C grep -q -m 1 -i -e "^PASS_MAX_DAYS\\>" "/etc/login.defs"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^PASS_MAX_DAYS\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
else
    if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
    fi
    cce="CCE-80647-1"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/login.defs" >> "/etc/login.defs"
    printf '%s\n' "$formatted_output" >> "/etc/login.defs"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Set Password Minimum Age"
if rpm --quiet -q shadow-utils; then
var_accounts_minimum_age_login_defs='1'
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^PASS_MIN_DAYS")
printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_minimum_age_login_defs"
if LC_ALL=C grep -q -m 1 -i -e "^PASS_MIN_DAYS\\>" "/etc/login.defs"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^PASS_MIN_DAYS\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
else
    if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
    fi
    cce="CCE-80648-9"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/login.defs" >> "/etc/login.defs"
    printf '%s\n' "$formatted_output" >> "/etc/login.defs"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if rpm --quiet -q shadow-utils; then
var_accounts_password_minlen_login_defs='15'
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^PASS_MIN_LEN")
printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_password_minlen_login_defs"
if LC_ALL=C grep -q -m 1 -i -e "^PASS_MIN_LEN\\>" "/etc/login.defs"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^PASS_MIN_LEN\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
else
    if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
    fi
    cce="CCE-80652-1"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/login.defs" >> "/etc/login.defs"
    printf '%s\n' "$formatted_output" >> "/etc/login.defs"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Ensure the Default Bash Umask is Set Correctly"
if rpm --quiet -q bash; then
var_accounts_user_umask='077'
grep -q "^\s*umask" /etc/bashrc && \
  sed -i -E -e "s/^(\s*umask).*/\1 $var_accounts_user_umask/g" /etc/bashrc
if ! [ $? -eq 0 ]; then
    echo "umask $var_accounts_user_umask" >> /etc/bashrc
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Ensure the Default C Shell Umask is Set Correctly"
var_accounts_user_umask='077'
grep -q "^\s*umask" /etc/csh.cshrc && \
  sed -i -E -e "s/^(\s*umask).*/\1 $var_accounts_user_umask/g" /etc/csh.cshrc
if ! [ $? -eq 0 ]; then
    echo "umask $var_accounts_user_umask" >> /etc/csh.cshrc
fi
echo "################## Ensure the Default Umask is Set Correctly in login.defs"
if rpm --quiet -q shadow-utils; then
var_accounts_user_umask='077'
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^UMASK")
printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_user_umask"
if LC_ALL=C grep -q -m 1 -i -e "^UMASK\\>" "/etc/login.defs"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^UMASK\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
else
    if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
    fi
    cce="CCE-82888-9"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/login.defs" >> "/etc/login.defs"
    printf '%s\n' "$formatted_output" >> "/etc/login.defs"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "################## Ensure the Default Umask is Set Correctly in /etc/profile"
var_accounts_user_umask='077'
readarray -t profile_files < <(find /etc/profile.d/ -type f -name '*.sh' -or -name 'sh.local')
for file in "${profile_files[@]}" /etc/profile; do
  grep -qE '^[^#]*umask' "$file" && sed -i -E "s/^(\s*umask\s*)[0-7]+/\1$var_accounts_user_umask/g" "$file"
done
if ! grep -qrE '^[^#]*umask' /etc/profile*; then
  echo "umask $var_accounts_user_umask" >> /etc/profile
fi
echo "################## Ensure the Logon Failure Delay is Set Correctly in login.defs"
if rpm --quiet -q shadow-utils; then
var_accounts_fail_delay='4'
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^FAIL_DELAY")
printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_fail_delay"
if LC_ALL=C grep -q -m 1 -i -e "^FAIL_DELAY\\>" "/etc/login.defs"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^FAIL_DELAY\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
else
    if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
    fi
    cce="CCE-84037-1"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/login.defs" >> "/etc/login.defs"
    printf '%s\n' "$formatted_output" >> "/etc/login.defs"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi