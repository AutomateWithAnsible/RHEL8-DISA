#!/bin/bash
##################### HIGH FINDINGS #####################
# Enable Dracut FIPS Module
if ( [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && ! ( [ "${container:-}" == "bwrap-osbuild" ] ) ); then
fips-mode-setup --enable
FIPS_CONF="/etc/dracut.conf.d/40-fips.conf"
if ! grep "^add_dracutmodules+=\" fips \"" $FIPS_CONF; then
    echo "add_dracutmodules+=\" fips \"" >> $FIPS_CONF
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Enable FIPS Mode
if ( [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && ! ( [ "${container:-}" == "bwrap-osbuild" ] ) ) && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then
var_system_crypto_policy='FIPS'
fips-mode-setup --enable
stderr_of_call=$(update-crypto-policies --set ${var_system_crypto_policy} 2>&1 > /dev/null)
rc=$?
if test "$rc" = 127; then
	echo "$stderr_of_call" >&2
	echo "Make sure that the script is installed on the remediated system." >&2
	echo "See output of the 'dnf provides update-crypto-policies' command" >&2
	echo "to see what package to (re)install" >&2
	false  # end with an error code
elif test "$rc" != 0; then
	echo "Error invoking the update-crypto-policies script: $stderr_of_call" >&2
	false  # end with an error code
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# set kernel parameter 'crypto.fips_enabled' to 1
fips-mode-setup --enable
# Configure System Cryptography Policy
var_system_crypto_policy='FIPS'
stderr_of_call=$(update-crypto-policies --set ${var_system_crypto_policy} 2>&1 > /dev/null)
rc=$?
if test "$rc" = 127; then
	echo "$stderr_of_call" >&2
	echo "Make sure that the script is installed on the remediated system." >&2
	echo "See output of the 'dnf provides update-crypto-policies' command" >&2
	echo "to see what package to (re)install" >&2
	false  # end with an error code
elif test "$rc" != 0; then
	echo "Error invoking the update-crypto-policies script: $stderr_of_call" >&2
	false  # end with an error code
fi
# Configure SSH Client to Use FIPS 140-2 Validated Ciphers: openssh.config
sshd_approved_ciphers='aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com'
if [ -e "/etc/crypto-policies/back-ends/openssh.config" ] ; then
    LC_ALL=C sed -i "/^.*Ciphers\s\+/d" "/etc/crypto-policies/back-ends/openssh.config"
else
    touch "/etc/crypto-policies/back-ends/openssh.config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/crypto-policies/back-ends/openssh.config"
cp "/etc/crypto-policies/back-ends/openssh.config" "/etc/crypto-policies/back-ends/openssh.config.bak"
# Insert at the end of the file
printf '%s\n' "Ciphers ${sshd_approved_ciphers}" >> "/etc/crypto-policies/back-ends/openssh.config"
# Clean up after ourselves.
rm "/etc/crypto-policies/back-ends/openssh.config.bak"
################### System needs to now be rebooted in order for the FIPS remediation to take effect!! ###################