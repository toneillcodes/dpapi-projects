$protect_directory = $Env:AppData + "\Microsoft\Protect"
#$user_sid = Get-ChildItem -Path $protect_directory -Directory | select-object -expandproperty Name
$user_sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if($user_sid) {
	$master_key_directory = $protect_directory + "\" + $user_sid
	if($master_key_directory) {
		echo "Master Key Directory: " $master_key_directory
		$master_key_list = Get-ChildItem -Path $master_key_directory -Directory | select-object -expandproperty Name
		if($master_key_list) {
			echo "Master Key List: " $master_key_list
		} else {
			echo "No master keys found"
		}
	} else {
		echo "ERROR: Unable to determine master key directory"
	}
} else {
	echo "ERROR: Unable to determine SID"
}
