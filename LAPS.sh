#!/bin/bash

set -x

####################################################################################################
#
#   MIT License
#
#   Copyright (c) 2016 University of Nebraska–Lincoln
#
#	Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.
#
####################################################################################################

function DecryptString() {
	# Usage: ~$ DecryptString "Encrypted String" "Salt" "Passphrase"
	echo "${1}" | /usr/bin/openssl enc -aes256 -d -a -A -S "${2}" -k "${3}"
}

apiUser=$(DecryptString "${4}" "Salt" "Passphrase")
apiPass=$(DecryptString "${5}" "Salt" "Passphrase")
resetUser="laps"


# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 6 AND, IF SO, ASSIGN TO "resetUser"
if [ "$6" != "" ] && [ "$resetUser" == "" ];then
resetUser=$6
fi

apiURL="jpsURL"
LogLocation="/var/log/Jamf_LAPS.log"

unEncryptedPassword=$(openssl rand -base64 10 | tr -d OoIi1lLS | head -c12;echo)
####################################################################
#
#            ┌─── openssl is used to create
#            │	a random Base64 string
#            │                    ┌── remove ambiguous characters
#            │                    │
# ┌──────────┴──────────┐	  ┌───┴────────┐
# openssl rand -base64 10 | tr -d OoIi1lLS | head -c12;echo
#                                            └──────┬─────┘
#                                                   │
#             prints the first 12 characters  ──────┘
#             of the randomly generated string
#

SALT="$(defaults read /var/root/Library/Preferences/com.company.scramble.plist SALT)"
K="$(defaults read /var/root/Library/Preferences/com.company.scramble.plist K)"
encryptedPassword=$(echo "${unEncryptedPassword}" | openssl enc -aes256 -a -A -S "${SALT}" -k "${K}")
echo "Encrypted Password Created with Salt: ${SALT} | Passphrase: ${K}"

####################################################################################################
#
# SCRIPT CONTENTS - DO NOT MODIFY BELOW THIS LINE
#
####################################################################################################

udid=$(system_profiler SPHardwareDataType | /usr/bin/awk '/Hardware UUID:/ { print $3 }')
xmlString="<?xml version=\"1.0\" encoding=\"UTF-8\"?><computer><extension_attributes><extension_attribute><name>LAPS</name><value>"$encryptedPassword"</value></extension_attribute></extension_attributes></computer>"
extAttName="\"LAPS\""
oldPasswordEncrypted=$(curl -s -f -u $apiUser:$apiPass -H "Accept: application/xml" $apiURL/JSSResource/computers/udid/$udid/subset/extension_attributes | xpath "//extension_attribute[name=$extAttName]" 2>/dev/null | awk -F'<value>|</value>' '{print $2}')
oldPasswordDecrypted=$(DecryptString "${oldPasswordEncrypted}" "${SALT}" "${K}")
# Logging Function for reporting actions
ScriptLogging(){

DATE=`date +%Y-%m-%d\ %H:%M:%S`
LOG="$LogLocation"

echo "$DATE" " $1" >> $LOG
}

ScriptLogging "======== Starting LAPS Update ========"
ScriptLogging "Checking parameters."

# Verify parameters are present
if [ "$apiUser" == "" ];then
    ScriptLogging "Error:  The parameter 'API Username' is blank.  Please specify a user."
    echo "Error:  The parameter 'API Username' is blank.  Please specify a user."
    ScriptLogging "======== Aborting LAPS Update ========"
    exit 1
fi

if [ "$apiPass" == "" ];then
    ScriptLogging "Error:  The parameter 'API Password' is blank.  Please specify a password."
    echo "Error:  The parameter 'API Password' is blank.  Please specify a password."
    ScriptLogging "======== Aborting LAPS Update ========"
    exit 1
fi

if [ "$resetUser" == "" ];then
    ScriptLogging "Error:  The parameter 'User to Reset' is blank.  Please specify a user to reset."
    echo "Error:  The parameter 'User to Reset' is blank.  Please specify a user to reset."
    ScriptLogging "======== Aborting LAPS Update ========"
    exit 1
fi

# Verify resetUser is a local user on the computer
checkUser=`dseditgroup -o checkmember -m $resetUser localaccounts | awk '{ print $1 }'`

if [[ "$checkUser" = "yes" ]];then
    echo "$resetUser is a local user on the Computer"
else
    echo "Error: $checkUser is not a local user on the Computer!"
    ScriptLogging "======== Aborting LAPS Update ========"
    exit 1
fi

ScriptLogging "Parameters Verified."

# Identify the location of the jamf binary for the jamf_binary variable.
CheckBinary (){
# Identify location of jamf binary.
jamf_binary=`/usr/bin/which jamf`


ScriptLogging "JAMF Binary is $jamf_binary"
}

# Verify the current User Password in Jamf LAPS
CheckoldPassword (){
ScriptLogging "Verifying password stored in LAPS."

if [ "$oldPasswordEncrypted" == "" ];then
    ScriptLogging "No Password is stored in LAPS."
    echo "No Password is stored in LAPS."
    oldPassword=None
else
    ScriptLogging "A Password was found in LAPS."
    echo "A Password was found in LAPS."
fi

passwdA=`dscl /Local/Default -authonly $resetUser $oldPasswordDecrypted`

if [ "$passwdA" == "" ];then
    ScriptLogging "Password stored in LAPS is correct for $resetUser."
    echo "Password stored in LAPS is correct for $resetUser."
else
    ScriptLogging "Error: Password stored in LAPS is not valid for $resetUser."
    echo "Error: Password stored in LAPS is not valid for $resetUser."
    oldPassword=""
fi
}

# Update the User Password
RunLAPS (){
ScriptLogging "Running LAPS..."
if [ "$oldPasswordEncrypted" == "" ];then
    ScriptLogging "Current password not available, proceeding with forced update for $resetUser."
    echo "Current password not available, proceeding with forced update."
    $jamf_binary resetPassword -username $resetUser -password $unEncryptedPassword
else
    ScriptLogging "Updating password for $resetUser."
    echo "Updating password for $resetUser."
    $jamf_binary changePassword -username $resetUser -oldPassword $oldPasswordDecrypted -password $unEncryptedPassword
fi
}

# Verify the new User Password
CheckNewPassword (){
ScriptLogging "Verifying new password for $resetUser."
passwdB=`dscl /Local/Default -authonly $resetUser $unEncryptedPassword`

if [ "$passwdB" == "" ];then
    ScriptLogging "New password for $resetUser is verified."
    echo "New password for $resetUser is verified."
else
    ScriptLogging "Error: Password reset for $resetUser was not successful!"
    echo "Error: Password reset for $resetUser was not successful!"
    ScriptLogging "======== Aborting LAPS Update ========"
    exit 1
fi
}

# Update the LAPS Extention Attribute
UpdateAPI (){
ScriptLogging "Recording new password for $resetUser into LAPS."
/usr/bin/curl -s -u ${apiUser}:${apiPass} -X PUT -H "Content-Type: text/xml" -d "${xmlString}" "${apiURL}/JSSResource/computers/udid/$udid"

sleep 1

lapsPasswordEncrypted=$(curl -s -f -u $apiUser:$apiPass -H "Accept: application/xml" $apiURL/JSSResource/computers/udid/$udid/subset/extension_attributes | xpath "//extension_attribute[name=$extAttName]" 2>/dev/null | awk -F'<value>|</value>' '{print $2}')
lapsPasswordDecrypted=$(DecryptString "${lapsPasswordEncrypted}" "${SALT}" "${K}")
ScriptLogging "Verifying LAPS password for $resetUser."
passwdC=`dscl /Local/Default -authonly $resetUser $lapsPasswordDecrypted`
if [ "$passwdC" == "" ];then
    ScriptLogging "LAPS password for $resetUser is verified."
    echo "LAPS password for $resetUser is verified."
else
    ScriptLogging "Error: LAPS password for $resetUser is not correct!"
    echo "Error: LAPS password for $resetUser is not correct!"
    ScriptLogging "======== Aborting LAPS Update ========"
exit 1
fi
}

CheckBinary
CheckoldPassword
RunLAPS
CheckNewPassword
UpdateAPI

ScriptLogging "======== LAPS Update Finished ========"
echo "LAPS Update Finished."

exit 0


