#!/bin/bash

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

function DecryptString() {
	# Usage: ~$ DecryptString "Encrypted String" "Salt" "Passphrase"
	echo "${1}" | /usr/bin/openssl enc -aes256 -d -a -A -S "${2}" -k "${3}"
}

apiUser=$(DecryptString "${4}" "Salt" "Passphrase")
apiPass=$(DecryptString "${5}" "Salt" "Passphrase")
LAPSuser="laps"
LAPSuserDisplay="laps"
LAPSaccountEvent="seedLapsUser"
LAPSaccountEventFVE="_notused"
LAPSrunEvent="runLapsMaintenance"

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

SALT=$(openssl rand -hex 8)
K=$(openssl rand -hex 12)

encryptedPassword=$(echo "${unEncryptedPassword}" | openssl enc -aes256 -a -A -S "${SALT}" -k "${K}")
echo "Password Encrypted with Salt: ${SALT} | Passphrase: ${K}"

# Write the Salt and Passphrase out to the Cslient for subsequent password changes.

defaults write /var/root/Library/Preferences/com.company.scramble.plist SALT  -string "${SALT}"
defaults write /var/root/Library/Preferences/com.company.scramble.plist K  -string "${K}"

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 4 AND, IF SO, ASSIGN TO "apiUser"
if [ "$4" != "" ] && [ "$apiUser" == "" ];then
apiUser=$4
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 5 AND, IF SO, ASSIGN TO "apiPass"
if [ "$5" != "" ] && [ "$apiPass" == "" ];then
apiPass=$5
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 6 AND, IF SO, ASSIGN TO "LAPSuser"
if [ "$6" != "" ] && [ "$LAPSuser" == "" ];then
LAPSuser=$6
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 7 AND, IF SO, ASSIGN TO "LAPSuserDisplay"
if [ "$7" != "" ] && [ "$LAPSuserDisplay" == "" ];then
LAPSuserDisplay=$7
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 8 AND, IF SO, ASSIGN TO "newPass"
if [ "$8" != "" ] && [ "$newPass" == "" ];then
newPass=$8
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 9 AND, IF SO, ASSIGN TO "LAPSaccountEvent"
if [ "$9" != "" ] && [ "$LAPSaccountEvent" == "" ];then
LAPSaccountEvent=$9
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 10 AND, IF SO, ASSIGN TO "LAPSaccountEventFVE"
# if [ "${10}" != "" ] && [ "$LAPSaccountEventFVE" == "" ];then
# LAPSaccountEventFVE="${10}"
# fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 11 AND, IF SO, ASSIGN TO "LAPSrunEvent"
if [ "${11}" != "" ] && [ "$LAPSrunEvent" == "" ];then
LAPSrunEvent="${11}"
fi

apiURL="jamfProURL"
LogLocation="/var/log/Jamf_LAPS.log"

####################################################################################################
#
# SCRIPT CONTENTS - DO NOT MODIFY BELOW THIS LINE
#
####################################################################################################

udid=$(system_profiler SPHardwareDataType | /usr/bin/awk '/Hardware UUID:/ { print $3 }')
xmlString="<?xml version=\"1.0\" encoding=\"UTF-8\"?><computer><extension_attributes><extension_attribute><name>LAPS</name><value>"$encryptedPassword"</value></extension_attribute></extension_attributes></computer>"
extAttName="\"LAPS\""
# FVEstatus=$(fdesetup status | grep -w "FileVault is" | awk '{print $3}' | sed 's/[.]//g')

# Logging Function for reporting actions
ScriptLogging(){

DATE=`date +%Y-%m-%d\ %H:%M:%S`
LOG="$LogLocation"

echo "$DATE" " $1" >> $LOG
}

ScriptLogging "======== Starting LAPS Account Creation ========"
ScriptLogging "Checking parameters."

# Verify parameters are present
if [ "$apiUser" == "" ];then
    ScriptLogging "Error:  The parameter 'API Username' is blank.  Please specify a user."
    echo "Error:  The parameter 'API Username' is blank.  Please specify a user."
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
fi

if [ "$apiPass" == "" ];then
    ScriptLogging "Error:  The parameter 'API Password' is blank.  Please specify a password."
    echo "Error:  The parameter 'API Password' is blank.  Please specify a password."
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
fi

if [ "$LAPSuser" == "" ];then
    ScriptLogging "Error:  The parameter 'LAPS Account Shortname' is blank.  Please specify a user to create."
    echo "Error:  The parameter 'LAPS Account Shortname' is blank.  Please specify a user to create."
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
fi

if [ "$LAPSuserDisplay" == "" ];then
    ScriptLogging "Error:  The parameter 'LAPS Account Displayname' is blank.  Please specify a user to create."
    echo "Error:  The parameter 'LAPS Account Displayname' is blank.  Please specify a user to create."
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
fi

if [ "$unEncryptedPassword" == "" ];then
    ScriptLogging "Error:  The parameter 'LAPS Password Seed' is blank.  Please specify a password to seed."
    echo "Error:  The parameter 'LAPS Password Seed' is blank.  Please specify a password to seed."
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
fi

if [ "$LAPSaccountEvent" == "" ];then
    ScriptLogging "Error:  The parameter 'LAPS Account Event' is blank.  Please specify a Custom LAPS Account Event."
    echo "Error:  The parameter 'LAPS Account Event' is blank.  Please specify a Custom LAPS Account Event."
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
fi


if [ "$LAPSrunEvent" == "" ];then
    ScriptLogging "Error:  The parameter 'LAPS Run Event' is blank.  Please specify a Custom LAPS Run Event."
    echo "Error:  The parameter 'LAPS Run Event' is blank.  Please specify a Custom LAPS Run Event."
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
fi

# Verify resetUser is not a local user on the computer
checkUser=`dseditgroup -o checkmember -m $LAPSuser localaccounts | awk '{ print $1 }'`

if [[ "$checkUser" = "yes" ]];then
    ScriptLogging "Error: $LAPSuser already exists as a local user on the Computer"
    echo "Error: $LAPSuser already exists as a local user on the Computer"
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
else
    ScriptLogging "$LAPSuser is not a local user on the Computer, proceeding..."
    echo "$LAPSuser is not a local user on the Computer, proceeding..."
fi

ScriptLogging "Parameters Verified."

# Identify the location of the jamf binary for the jamf_binary variable.
CheckBinary (){
# Identify location of jamf binary.
jamf_binary=`/usr/bin/which jamf`


ScriptLogging "JAMF Binary is $jamf_binary"
}

# Create the User Account
CreateLAPSaccount (){
    ScriptLogging "Creating LAPS Account..."
    echo "Creating LAPS Account..."
    $jamf_binary createAccount -username $LAPSuser -realname $LAPSuserDisplay -password "$unEncryptedPassword" -home /var/$LAPSuser -shell /bin/bash -admin -hiddenUser -suppressSetupAssistant
    ScriptLogging "LAPS Account Created..."
        echo "LAPS Account Created..."
# The following isn't used if the Laps user will not be an FDE User
#    else
#        $jamf_binary policy -event $LAPSaccountEventFVE
#        ScriptLogging "LAPS Account Created with FVE..."
#        echo "LAPS Account Created with FVE..."
#    fi
}

# Update the LAPS Extention Attribute
UpdateAPI (){
    ScriptLogging "Recording new password for $LAPSuser into LAPS."
    /usr/bin/curl -s -f -u ${apiUser}:${apiPass} -X PUT -H "Content-Type: text/xml" -d "${xmlString}" "${apiURL}/JSSResource/computers/udid/$udid"
}

# Check to see if the account is authorized with FileVault 2
# FVEcheck (){
#     userCheck=`fdesetup list | awk -v usrN="$LAPSuserDisplay" -F, 'index($0, usrN) {print $1}'`
#         if [ "${userCheck}" == "${LAPSuserDisplay}" ]; then
#             ScriptLogging "$LAPSuserDisplay is enabled for FileVault 2."
#             echo "$LAPSuserDisplay is enabled for FileVault 2."
#         else
#             ScriptLogging "Error: $LAPSuserDisplay is not enabled for FileVault 2."
#             echo "Error: $LAPSuserDispaly is not enabled for FileVault 2."
#         fi
# }

# If FileVault Encryption is enabled, verify account.
# FVEverify (){
#     ScriptLogging "Checking FileVault Status..."
#     echo "Checking FileVault Status..."
#     if [ "$FVEstatus" == "On" ];then
#         ScriptLogging "FileVault is enabled, checking $LAPSuserDisplay..."
#         echo "FileVault is enabled, checking $LAPSuserDisplay..."
#         FVEcheck
#     else
#         ScriptLogging "FileVault is not enabled."
#         echo "FileVault is not enabled."
#     fi
# }


CheckBinary
UpdateAPI
CreateLAPSaccount
UpdateAPI
# FVEverify

ScriptLogging "======== LAPS Account Creation Complete ========"
echo "LAPS Account Creation Finished."

# Run LAPS Password Randomization
# $jamf_binary policy -event $LAPSrunEvent

exit 0


