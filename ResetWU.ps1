#######################################################################################################
# This script resets the Windows update components and solves most of the Windows Update related      #
# problems. If it fails in first attempt, make sure to run it again.                                  #
#                                                                                                     #
#    ! DISCLAIMER: This script is provided on 'AS IS' basis without any warranty. !                   #
#                                                                                                     #
# Author: Aslam Khan (https://windospc.com)                                                           #
# Created: 05-Dec-2022                                                                                #
# Modified: 05-Sep-2023                                                                               #
# Version: 1.2.1                                                                                      #
# Changelog:                                                                                          #
#  V1.2.1 => Improved the script to remove staged windows packages from registry.                     #
#  V1.2.0 => Added functionality to check for admin rights while running the script. Improved output. #
#  V1.1.6 => Improved the Stop-WUSerivces function to avoid restarting of services automatically.     #
#  V1.1.5 => Changed the order of functions to avoid failing to clear SoftwareDistribution folder.    #
#  V1.1.4 => Added function to remove pending.xml by taking ownership of the file.                    #
#  V1.1.3 => Improved the error handling and message display.                                         #
#  V1.1.2 => Added better error handling in the script.                                               #
#  V1.1.1 => Updated the script to clear the staged Windows packages.                                 #
#######################################################################################################

# Setting current script version.
$Version = "1.2.1"

# Setting error action preference
$ErrorActionPreference = 'Stop'

#################### Defining the functions required for the script to run ##########################
# Setting the name of the services related to Windows Update.
[String[]]$Services = "cryptsvc", "wuauserv", "msiserver", "dosvc", "appidsvc", "bits", "trustedinstaller"

# Function to start Windows Update related services.
Function Start-WUServices {
	[CmdletBinding(DefaultParameterSetName='Services')]
	Param (
        [Parameter(Mandatory=$true, Position=0, ParameterSetName='Services')]
        [String[]] $Services
	)
    Write-Host "Starting Windows Update related services..."
    #$Services = @("cryptsvc", "wuauserv", "msiserver", "dosvc", "appidsvc", "bits", "trustedinstaller")
    ForEach ($Svc in $Services) {
        If(Get-Service -Name $Svc -ErrorAction SilentlyContinue) {
            If ($Svc -eq "wuauserv" -or $Svc -eq "cryptsvc") {
                Set-Service $svc -StartupType Automatic -ErrorAction Ignore
                Start-Service $Svc -ErrorAction Ignore
            } Else {
                Set-Service $svc -StartupType Manual -ErrorAction Ignore
                Start-Service $Svc -ErrorAction Ignore
            }
        }
    }
    Write-Output "Services started successfully."
}

# Function to stop Windows Update related services
Function Stop-WUServices {
	[CmdletBinding(DefaultParameterSetName='Services')]
	Param (
        [Parameter(Mandatory=$true, Position=0, ParameterSetName='Services')]
        [String[]] $Services
	)
    #$Services = @("cryptsvc", "wuauserv", "msiserver", "dosvc", "appidsvc", "bits", "trustedinstaller")
	Write-Host "Trying to stop the services...`n"
    ForEach ($Service in $Services) {
        If(Get-Service -Name $Service -ErrorAction SilentlyContinue) {
            #Write-Host "`nStopping service: $service"
            Stop-Service -Name $Service -Force -NoWait -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
			If ((Get-Service $Service).Status -ieq "stopped") {
                Write-Host "[$Service]:" -F Cyan -NoNewLine
				Write-Host " Service stopped successfully.`n"
                If ($Service -ilike "wuauserv" -or $Service -ilike "cryptsvc") {
                    Set-Service $Service -StartupType Disabled -ErrorAction SilentlyContinue
                }
            } Else {
                Write-Host "[$Service]: Service could not be stopped normally. Trying to stop the service forcefully." -F Yellow
                $processID = (Get-WmiObject Win32_service | ? {$_.Name -eq $Service}).ProcessID
                If($processID) {
					Try {
						taskkill /f /pid $processID > $null
						Set-Service $Service -StartupType Disabled -ErrorAction SilentlyContinue
						Write-Host "[$Service]:" -F Cyan -NoNewLine
						Write-Host " Service stopped successfully.`n"
					} Catch {
						Write-Host $Error[0].Exception.Message.TrimEnd() -F Yellow -B Red
						Write-Host "[$Service]: Unable to stop the service.`n`nStarting the services again." -F Yellow
						Start-WUServices $Services
						Write-Host "`nPlease try to run the script again..." -F Yellow -B Magenta
					}
				} Else {
					Write-Host "[$Service]:" -F Cyan -NoNewLine
					Write-Host " Service stopped successfully.`n"
				}
            }
        }
    }
}

# Function to take ownership and full control of any any file or folder.
Function Take-Ownership {
    [CmdletBinding(DefaultParameterSetName='Path')]
	Param (
        [Parameter(Mandatory=$true, Position=0, ParameterSetName='Path')]
        [String[]] $Path
	)
    If ((Get-Item $Path).PSIsContainer) {
        # Setting permissions for the folder.
	    Try {
		    $NewOwner = New-Object System.Security.Principal.NTAccount("", "Everyone")
		    $Acl = Get-Acl $Path
		    $Acl.SetOwner($NewOwner)
            $Acl.SetAccessRuleProtection($true,$false)
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","FullControl","ContainerInherit,Objectinherit","none","Allow")
            $Acl.AddAccessRule($AccessRule)
            Set-Acl $Path $Acl
		    Write-Host "Successfully set the permissions for folder: $Path."
	    } Catch {
		    Write-Host $Error[0].Exception.Message.TrimEnd() -F Red -B Black
	    }
    } Else {
        # Setting permissions for the file.
        Try {
		    $NewOwner = New-Object System.Security.Principal.NTAccount("", "Everyone")
		    $Acl = Get-Acl $Path
		    $Acl.SetOwner($NewOwner)
            $Acl.SetAccessRuleProtection($true,$false)
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","FullControl","none","none","Allow")
            $Acl.AddAccessRule($AccessRule)
            Set-Acl $Path $Acl
		    Write-Host "Successfully set the permissions for file: $Path."
	    } Catch {
		    Write-Host $Error[0].Exception.Message.TrimEnd() -F Red -B Black
	    }
    }
}

# Function to take ownership and full control of any Registry key.
Function Take-RegOwnership {
<#  
    Developed for PowerShell v4.0
    Required Admin privileges
    Links:
        http://shrekpoint.blogspot.ru/2012/08/taking-ownership-of-dcom-registry.html
        http://www.remkoweijnen.nl/blog/2012/01/16/take-ownership-of-a-registry-key-in-powershell/
        https://powertoe.wordpress.com/2010/08/28/controlling-registry-acl-permissions-with-powershell/
    
    .EXAMPLES
    group BULTIN\Users takes full control of key and all subkeys
    Take-Permissions "HKLM" "SOFTWARE\test"

    group Everyone takes full control of key and all subkeys
    Take-Permissions "HKLM" "SOFTWARE\test" "S-1-1-0"

    group Everyone takes full control of key WITHOUT subkeys
    Take-Permissions "HKLM" "SOFTWARE\test" "S-1-1-0" $false
#>
    param($rootKey, $key, [System.Security.Principal.SecurityIdentifier]$sid = 'S-1-5-32-545', $recurse = $true)

    switch	-regex ($rootKey) {
        'HKCU|HKEY_CURRENT_USER'    { $rootKey = 'CurrentUser' }
        'HKLM|HKEY_LOCAL_MACHINE'   { $rootKey = 'LocalMachine' }
        'HKCR|HKEY_CLASSES_ROOT'    { $rootKey = 'ClassesRoot' }
        'HKCC|HKEY_CURRENT_CONFIG'  { $rootKey = 'CurrentConfig' }
        'HKU|HKEY_USERS'            { $rootKey = 'Users' }
    }

    ### Step 1 - escalate current process's privilege
    # get SeTakeOwnership, SeBackup and SeRestore privileges before executes next lines, script needs Admin privilege
    $import = '[DllImport("ntdll.dll")] public static extern int RtlAdjustPrivilege(ulong a, bool b, bool c, ref bool d);'
    $ntdll = Add-Type -Member $import -Name NtDll -PassThru
    $privileges = @{ SeTakeOwnership = 9; SeBackup =  17; SeRestore = 18 }
    ForEach ($i in $privileges.Values) {
        $null = $ntdll::RtlAdjustPrivilege($i, 1, 0, [ref]0)
    }

    Function Take-KeyPermissions {
        param($rootKey, $key, $sid, $recurse, $recurseLevel = 0)

        ### Step 2 - get ownerships of key - it works only for current key
        $regKey = [Microsoft.Win32.Registry]::$rootKey.OpenSubKey($key, 'ReadWriteSubTree', 'TakeOwnership')
        $acl = New-Object System.Security.AccessControl.RegistrySecurity
        $acl.SetOwner($sid)
        $regKey.SetAccessControl($acl)

        ### Step 3 - enable inheritance of permissions (not ownership) for current key from parent
        $acl.SetAccessRuleProtection($false, $false)
        $regKey.SetAccessControl($acl)

        ### Step 4 - only for top-level key, change permissions for current key and propagate it for subkeys
        # to enable propagations for subkeys, it needs to execute Steps 2-3 for each subkey (Step 5)
        If ($recurseLevel -eq 0) {
            $regKey = $regKey.OpenSubKey('', 'ReadWriteSubTree', 'ChangePermissions')
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule($sid, 'FullControl', 'ContainerInherit', 'None', 'Allow')
            $acl.ResetAccessRule($rule)
            $regKey.SetAccessControl($acl)
        }

        ### Step 5 - recursively repeat steps 2-5 for subkeys
        If ($recurse) {
            ForEach($subKey in $regKey.OpenSubKey('').GetSubKeyNames()) {
                Take-KeyPermissions $rootKey ($key+'\'+$subKey) $sid $recurse ($recurseLevel+1)
            }
        }
    }

    Take-KeyPermissions $rootKey $key $sid $recurse
}

#####################################################################################################

############################ Starting the main script ###############################################

# Setting Console width and height for the script.
$ErrorActionPreference = 'SilentlyContinue'
[console]::WindowWidth=105; 
[console]::WindowHeight=35; 
[console]::BufferWidth=[console]::WindowWidth
Clear-Host
$ErrorActionPreference = 'Stop'

# Displaying the header message
Write-Host "`n#######################################################################################################
# This script resets the Windows update components and solves most of the Windows Update related      #
# problems. If it fails in first attempt, make sure to run it again.                                  #
#                                                                                                     #
#    ! DISCLAIMER: This script is provided on 'AS IS' basis without any warranty. !                   #
#                                                                                                     #
# Author: Aslam Khan (https://windospc.com)                                                           #
# Created: 05-Dec-2022                                                                                #
# Modified: 05-Sep-2023                                                                               #
# Version: $Version                                                                                      #
#######################################################################################################`n" -F Gray -B Black
Start-Sleep -Seconds 2

# Step 0: Checking if script is running with administrative rights.
If (!(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Write-Host "`n-------------------------------------------------------------------------------------------------------" -F Yellow -B Black
	Write-Host "| [Warning]: The script is not running with administrative rights!                                    |" -F Yellow -B Black
	Write-Host "| Please start PowerShell with admin rights and run the script again.                                 |" -F Yellow -B Black
	Write-Host "-------------------------------------------------------------------------------------------------------`n" -F Yellow -B Black
	Start-Sleep	5
	Exit
}

# Step 1: Try to stop Windows Update Services.
Write-Host "`n-------------------------------------------------------------------------------------------------------" -F Green -B Black
Write-Host "| Stopping Windows Update Related Services.                                                           |" -F Green -B Black
Write-Host "-------------------------------------------------------------------------------------------------------" -F Green -B Black
Stop-WUServices $Services
# Start-Sleep -Seconds 3

# Step 2: Clearing the Windows Update database folders
Write-Host "`n-------------------------------------------------------------------------------------------------------" -F Green -B Black
Write-Host "| Removing Windows Update Database folders.                                                           |" -F Green -B Black
Write-Host "-------------------------------------------------------------------------------------------------------" -F Green -B Black
Start-Sleep -Seconds 1
$Folders = @("$env:WINDIR\SoftwareDistribution", "$env:WINDIR\System32\catroot2")
ForEach ($Folder in $Folders) {
	If ($Folder -ilike "*SoftwareDistribution*") { $FName = "SoftwareDistribution" } Else { $FName = "catroot2" }
	Write-Host "Clearing the folder: $Folder"
	If(Test-Path "$Folder*") {
		# The folder exists, trying to remove it.
        Try {
            Remove-Item "$Folder*" -Recurse -Force #-ErrorAction Stop
			Write-Host "[$FName]:" -F Cyan -NoNewLine
			Write-Host " Cleared successfully.`n"
		} Catch {
			If ($Folder -like "*SoftwareDistribution*") {
				Write-Host "[$FName]:"$Error[0].Exception.Message.TrimEnd() -F Red -B Black
				Write-Host "[$FName]: Failed to clear the folder.`n" -F Yellow
				Start-WUServices $Services
				Write-Host "`nPlease try to run the script again.`n" -F Yellow -B Red
				Exit
			} Else {
				Write-Host "[$FName]:"$Error[0].Exception.Message.TrimEnd() -F Red -B Black
				Write-Host "[$FName]: Failed to clear the folder.`nMoving on.`n" -F Yellow
			}
		}
    } Else {
		# The folder doesn't exist, no need to remove it.
		Write-Host "[$FName]:" -F Cyan -NoNewLine
		Write-Host " Cleared successfully.`n"
	}
}

# Step 3: Removing QMGR data files
Write-Host "`n-------------------------------------------------------------------------------------------------------" -F Green -B Black
Write-Host "| Removing QMGR Data files.                                                                           |" -F Green -B Black
Write-Host "-------------------------------------------------------------------------------------------------------" -F Green -B Black
Start-Sleep -Seconds 1
Try {
	Remove-Item "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -Force
	Remove-Item "$env:ALLUSERSPROFILE\Microsoft\Network\Downloader\qmgr*.dat" -Force
	Write-Host "[QMGR]:" -F Cyan -NoNewLine
	Write-Host " Successfully removed old QMGR data files.`n"
} Catch {
	Write-Host $Error[0].Exception.Message.TrimEnd() -F Red -B Black
	Write-Host "[QMGR]: Failed to remove the QMGR data files. Moving on.`n" -F Yellow
}

# Step 4: Removing pending XML
Write-Host "`n-------------------------------------------------------------------------------------------------------" -F Green -B Black
Write-Host "| Removing Pending.xml file.                                                                          |" -F Green -B Black
Write-Host "-------------------------------------------------------------------------------------------------------" -F Green -B Black
Start-Sleep -Seconds 1
$File = "$env:SystemRoot\WinSxS\pending.xml"
If(Test-Path $File) {
	Try {
		Take-Ownership $File
		Remove-Item $File -Force
		Write-Host "[Pending.xml]:" -F Cyan -NoNewLine
		Write-Host " Successfully removed the pending XML file.`n"
	} Catch {
		Write-Host "[Pending.xml]:"$Error[0].Exception.Message.TrimEnd() -F Red -B Black
	}
} Else {
	Write-Host "[Pending.xml]:" -F Cyan -NoNewLine
	Write-Host " Pending XML file not present. Moving on.`n"
}

# Step 5: Removing old Windows Update log
Write-Host "`n-------------------------------------------------------------------------------------------------------" -F Green -B Black
Write-Host "| Removing old Windows Update log file.                                                               |" -F Green -B Black
Write-Host "-------------------------------------------------------------------------------------------------------" -F Green -B Black
Start-Sleep -Seconds 1
If (Test-Path "$env:SystemRoot\WindowsUpdate.log") {
	Try {
		Remove-Item $env:SystemRoot\WindowsUpdate.log -Force #-ErrorAction Stop
		Write-Host "[WindowsUpdate.log]:" -F Cyan -NoNewLine
		Write-Host " Successfully removed the log file.`n"
	} Catch {
		Write-Host $Error[0].Exception.Message.TrimEnd() -F Red -B Black
		Write-Host "[WindowsUpdate.log]: Failed to remove the log file. Moving on.`n" -F Yellow
	}
} Else {
	Write-Host "[WindowsUpdate.log]:" -F Cyan -NoNewLine
	Write-Host " Log file does not exist. Moving on.`n"
}
	

# Step 6: Resetting Windows Update services secuirty descriptors
Write-Host "`n-------------------------------------------------------------------------------------------------------" -F Green -B Black
Write-Host "| Resetting the Windows Update services security descriptors.                                         |" -F Green -B Black
Write-Host "-------------------------------------------------------------------------------------------------------" -F Green -B Black
Start-Sleep -Seconds 1
Try {
	"sc.exe sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)" > $null
	"sc.exe sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)" > $null
	<# "sc.exe sdset wuauserv D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLCRSDRCWDWO;;;SO)(A;;CCLCSWRPWPDTLOCRRC;;;SY)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;WD)"
	"sc.exe sdset bits D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLCRSDRCWDWO;;;SO)(A;;CCLCSWRPWPDTLOCRRC;;;SY)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;WD)"
	"sc.exe sdset cryptsvc D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLCRSDRCWDWO;;;SO)(A;;CCLCSWRPWPDTLOCRRC;;;SY)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;WD)"
	"sc.exe sdset trustedinstaller D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLCRSDRCWDWO;;;SO)(A;;CCLCSWRPWPDTLOCRRC;;;SY)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;WD)" #>
	Write-Host "[SDSET]:" -F Cyan -NoNewLine
	Write-Host " Successfully reset the security descriptors of Windows Update Services.`n"
} Catch {
	Write-Host $Error[0].Exception.Message.TrimEnd() -F Red -B Black
	Write-Host "[SDSET]: Failed to reset WU services secuirty descriptors. Moving on.`n" -F Yellow
}

# Step 7: Registring Windows update DLLs again.
Write-Host "`n-------------------------------------------------------------------------------------------------------" -F Green -B Black
Write-Host "| Registering Windows Update DLLs again.                                                              |" -F Green -B Black
Write-Host "-------------------------------------------------------------------------------------------------------" -F Green -B Black
Start-Sleep -Seconds 1
#Set-Location $env:systemroot\system32
Try {
	regsvr32.exe /s atl.dll
	regsvr32.exe /s urlmon.dll
	regsvr32.exe /s mshtml.dll
	regsvr32.exe /s shdocvw.dll
	regsvr32.exe /s browseui.dll
	regsvr32.exe /s jscript.dll
	regsvr32.exe /s vbscript.dll
	regsvr32.exe /s scrrun.dll
	regsvr32.exe /s msxml.dll
	regsvr32.exe /s msxml3.dll
	regsvr32.exe /s msxml6.dll
	regsvr32.exe /s actxprxy.dll
	regsvr32.exe /s softpub.dll
	regsvr32.exe /s wintrust.dll
	regsvr32.exe /s dssenh.dll
	regsvr32.exe /s rsaenh.dll
	regsvr32.exe /s gpkcsp.dll
	regsvr32.exe /s sccbase.dll
	regsvr32.exe /s slbcsp.dll
	regsvr32.exe /s cryptdlg.dll
	regsvr32.exe /s oleaut32.dll
	regsvr32.exe /s ole32.dll
	regsvr32.exe /s shell32.dll
	regsvr32.exe /s initpki.dll
	regsvr32.exe /s wuapi.dll
	regsvr32.exe /s wuaueng.dll
	regsvr32.exe /s wuaueng1.dll
	regsvr32.exe /s wucltui.dll
	regsvr32.exe /s wups.dll
	regsvr32.exe /s wups2.dll
	regsvr32.exe /s wuweb.dll
	regsvr32.exe /s qmgr.dll
	regsvr32.exe /s qmgrprxy.dll
	regsvr32.exe /s wucltux.dll
	regsvr32.exe /s muweb.dll
	regsvr32.exe /s wuwebv.dll
	Write-Host "[Regsvr32]:" -F Cyan -NoNewLine
	Write-Host " Successfully registered Windows Update DLLs.`n"
} Catch {
	Write-Host $Error[0].Exception.Message.TrimEnd() -F Red -B Black
	Write-Host "[Regsvr32]: Failed to re-register the Windows update DLLs. Moving on.`n" -F Yellow
}

# Step 8: Deleting all BITS jobs.
Write-Host "`n-------------------------------------------------------------------------------------------------------" -F Green -B Black
Write-Host "| Deleting all BITS jobs.                                                                             |" -F Green -B Black
Write-Host "-------------------------------------------------------------------------------------------------------" -F Green -B Black
Start-Sleep -Seconds 1
Try {
	Get-BitsTransfer | Remove-BitsTransfer
	Write-Host "[BITS]:" -F Cyan -NoNewLine
	Write-HOst " Successfully removed the BITS jobs.`n"
} Catch {
	Write-Host $Error[0].Exception.Message.TrimEnd() -F Red -B Black
	Write-Host "[BITS]: Failed to delete the BITS jobs. Moving on.`n" -F Yellow
}

# Step 9: Removing Staged Windows Update packages causing Windows Update issue.
Write-Host "`n-------------------------------------------------------------------------------------------------------" -F Green -B Black
Write-Host "| Removing Staged Windows packages.                                                                   |" -F Green -B Black
Write-Host "-------------------------------------------------------------------------------------------------------" -F Green -B Black
Start-Sleep -Seconds 1
$StgPkg = $null
Try {
	$StgPkg = Get-WindowsPackage -Online | where {$_.PackageState -eq 'Staged'}
	If($StgPkg) {
		Write-Host "Number of staged packages: $($StgPkg.Count)"
		ForEach ($Pkg in $StgPkg) {
			Write-Host "Trying to remove the package: $($Pkg.PackageName)"
			Try {
				#Remove-WindowsPackage -PackageName $Pkg.PackageName -Online –NoRestart
                #$PkgPath1 = "C:\Windows\servicing\Packages\$($Pkg.PackageName).cat"
				#$PkgPath2 = "C:\Windows\servicing\Packages\$($Pkg.PackageName).mum"
                $PkgRegPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\$($Pkg.PackageName)"
                If(Test-Path "HKLM:\$PkgRegPath") {
                    reg export "HKLM\$PkgRegPath" "C:\Temp\$($Pkg.PackageName).reg" /y > $null
                    Write-Host "[StgPkg]:" -F Cyan -NoNewLine
                    Write-Host " Registry key backup created: C:\Temp\$($Pkg.PackageName).reg"
                    Take-RegOwnership "HKLM" $PkgRegPath "S-1-1-0"
                    Remove-Item -Path "HKLM:\$PkgRegPath" -Force -Recurse
	    			Write-Host "[StgPkg]:" -F Cyan -NoNewLine
		    		Write-Host " Removed the package successfully.`n"
                } Else {
                    Write-Host "[StgPkg]:" -F Cyan -NoNewLine
		    		Write-Host " Registry entry for the package not found. Moving on.`n"
                }
			} Catch {
				Write-Host $Error[0].Exception.Message.TrimEnd() -F Red -B Black
				Write-Host "[StgPkg]: Failed to remove the package.`n" -F Yellow
			}
		}
	} Else {
		Write-Host "No Staged packages found. Moving on.`n"
	}
} Catch {
	Write-Host "[StgPkg]:"$Error[0].Exception.Message.TrimEnd() -F Red -B Black
	Write-Host "[StgPkg]: Failed to get the list of staged packages. Moving on.`n" -F Yellow
}
#Write-Host "Moving on."

# Step 10: Starting Windows update services again.
Write-Host "`n-------------------------------------------------------------------------------------------------------" -F Green -B Black
Write-Host "| Starting Windows Update Related Services.                                                           |" -F Green -B Black
Write-Host "-------------------------------------------------------------------------------------------------------" -F Green -B Black
Start-Sleep -Seconds 1
Start-WUServices $Services
Write-Host "`nPlease restart the computer and check for Windows Updates again... `n`n" -F Yellow #-B Magenta
#Pause
Exit
############################### Script END ######################################################################