#!/bin/bash

UNAME_S=`uname -s`

ard () {
	ARD_CMD=$1

	# /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
	mvar=$(ps ax | grep -i ardagent | grep -c -v grep)
	if [ $mvar -eq 1 ]; then
		echo "ARD running"
	else
		echo "No ARD process found"
	fi


	# /System/Library/LaunchDaemons/com.apple.screensharing.plist
	# 
	mvar=`ps ax | grep -i screensharingd | grep -c -v grep`
	if [ $mvar -eq 1 ]; then
		echo "Screen sharing running"
	else
		echo "No Screen sharing daemon found"
	fi
	

	# sudo launchctl kill KILL system/com.apple.screensharing

		# https://apple.stackexchange.com/questions/278744/command-line-enable-remote-login-and-remote-management
	# https://support.apple.com/en-us/HT201710
	# sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.screensharing.plist

	ARD_KICKSTART=/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart

	# https://wiki.mozilla.org/ReleaseEngineering/How_To/Access_Machines_via_VNC
	# $ARD_KICKSTART -configure -allowAccessFor -allUsers -privs -all
	#  -activate
	# sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -access -on -users admin -privs -all -restart -agent -menu

	# VNC
	# $ARD_KICKSTART -configure -clientopts -setvnclegacy -vnclegacy yes

	# VNC password
	# $ARD_KICKSTART -configure -clientopts -setvncpw -vncpw supersecret

	# restart
	# $ARD_KICKSTART -restart -agent -console

	# listen only on local interface
	# sudo defaults write /Library/Preferences/com.apple.RemoteManagement.plist VNCOnlyLocalConnections -bool yes
	
	# In newer versions of macOS, screen sharing will automatically re-lock the screen when you disconnect if it was locked when you first connected. To change this behavior, use:
	# sudo defaults write /Library/Preferences/com.apple.RemoteManagement RestoreMachineState -bool NO

	# https://www.jamf.com/jamf-nation/discussions/1989/reporting-ard-status

	#!/bin/sh
	#mvar=$(ps ax | grep -c -i "[Aa]rdagent")
	#if [ $mvar -eq 1 ]; then
	#echo "<result>Running</result>"
	#else 
	#echo "<result>Not Running</result>"
	#fi

}

# https://feeding.cloud.geek.nz/posts/usual-server-setup/

init_linux () {
	sudo apt-get -y install openssh-server net-tools vim nano etckeeper git sudo
}

# https://askubuntu.com/questions/47311/how-do-i-disable-my-system-from-going-to-sleep

initialize_insomnia () {
	#	● sleep.target - Sleep
	#   Loaded: loaded (/lib/systemd/system/sleep.target; static; vendor preset: enabled)
	#   Active: inactive (dead)
	#   Docs: man:systemd.special(7)

	#	● sleep.target
	#   Loaded: masked (Reason: Unit sleep.target is masked.)
	#   Active: inactive (dead)

	sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

	# OR

	# gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-timeout '0'
	# gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout '0'

	# dconf read /org/gnome/settings-daemon/plugins/power/lid-close-battery-action 'nothing'
	# dconf read /org/gnome/settings-daemon/plugins/power/lid-close-ac-action 'nothing'
	# dconf read /org/gnome/settings-daemon/plugins/power/idle-dim false

	# OR

	# sudo vi /etc/default/acpi-support # and then set SUSPEND_METHODS="none"
	# sudo /etc/init.d/acpid restart

}

NewLocalAdminUser () {
	$USER_
	/usr/sbin/usermod -a -G sudo user
}

add_user_to_sudoers () {
	SUDO_USER=${1:-${USER}}
	/usr/sbin/usermod -a -G sudo $SUDO_USER
}

enable_firewall () {
	apt install ufw
	ufw allow OpenSSH
	ufw enable

}


# sudo update-alternatives --config editor



if [ "x$UNAME_S" == "xDarwin" ] ; then
	
	ard status

	# https://apple.stackexchange.com/questions/278744/command-line-enable-remote-login-and-remote-management

	# SSH Enable
	# sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist

elif [ "x$UNAME_S" == "xLinux" ] ; then

	# init_linux

else

	echo "Unsupported OS: $UNAME_S"
	exit 1

fi