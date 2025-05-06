$protect_directory = $Env:AppData + "\Microsoft\Protect"
$user_sid = dir $protect_directory | select-object -expandproperty Name
$master_key_directory = $protect_directory + "\" + $user_sid
$master_key_list = dir $master_key_directory | select-object -expandproperty Name
echo $master_key_list
