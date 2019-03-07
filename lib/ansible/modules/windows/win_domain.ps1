#!powershell
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

# WANT_JSON
# POWERSHELL_COMMON

Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"

# FUTURE: consider action wrapper to manage reboots and credential changes

Function Ensure-Prereqs {
    $gwf = Get-WindowsFeature AD-Domain-Services
    If($gwf.InstallState -ne "Installed") {
        $result.changed = $true

        If($check_mode) {
            Exit-Json $result
        }
        $awf = Add-WindowsFeature AD-Domain-Services
        # FUTURE: check if reboot necessary
    }
}

$parsed_args = Parse-Args $args -supports_check_mode $true
$check_mode = Get-AnsibleParam $parsed_args "_ansible_check_mode" -default $false
$dns_domain_name = Get-AnsibleParam $parsed_args "dns_domain_name" -failifempty $true
$domain_netbios_name = Get-AnsibleParam $parsed_args "domain_netbios_name"
$safe_mode_admin_password = Get-AnsibleParam $parsed_args "safe_mode_password" -failifempty $true
$database_path = Get-AnsibleParam $parsed_args "database_path" -type "path"
$sysvol_path = Get-AnsibleParam $parsed_args "sysvol_path" -type "path"

$forest = $null

# FUTURE: support down to Server 2012?
If([System.Environment]::OSVersion.Version -lt [Version]"6.3.9600.0") {
    Fail-Json -message "win_domain requires Windows Server 2012R2 or higher"
}

$result = @{changed=$false; reboot_required=$false}

# FUTURE: any sane way to do the detection under check-mode *without* installing the feature?

Ensure-Prereqs

$forest = $null
try {
    # Cannot use Get-ADForest as that requires credential delegation, the below does not
    $forest_context = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext -ArgumentList Forest, $dns_domain_name
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($forest_context)
} catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException] { }

If(-not $forest) {
    $result.changed = $true

    If(-not $check_mode) {
        $sm_cred = ConvertTo-SecureString $safe_mode_admin_password -AsPlainText -Force

        $install_forest_args = @{
            DomainName=$dns_domain_name;
            SafeModeAdministratorPassword=$sm_cred;
            Confirm=$false;
            SkipPreChecks=$true;
            InstallDns=$true;
            NoRebootOnCompletion=$true;
        }
        if ($database_path) {
            $install_forest_args.DatabasePath = $database_path
        }
        if ($sysvol_path) {
            $install_forest_args.SysvolPath = $sysvol_path
        }
        if ($domain_netbios_name) {
            $install_forest_args.DomainNetBiosName = $domain_netbios_name
        }

        $iaf = $null
        try {
            $iaf = Install-ADDSForest @install_forest_args
        } catch [Microsoft.DirectoryServices.Deployment.DCPromoExecutionException] {
            # ExitCode 15 == 'Role change is in progress or this computer needs to be restarted.'
            # DCPromo exit codes details can be found at https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/troubleshooting-domain-controller-deployment
            if ($_.Exception.ExitCode -eq 15) {
                $result.reboot_required = $true
            } else {
                Fail-Json -obj $result -message "Failed to install ADDSForest with DCPromo: $($_.Exception.Message)"
            }
        }

        if ($null -ne $iaf) {
            $result.reboot_required = $iaf.RebootRequired

            # The Netlogon service is set to auto start but is not started. This is
            # required for Ansible to connect back to the host and reboot in a
            # later task. Even if this fails Ansible can still connect but only
            # with ansible_winrm_transport=basic so we just display a warning if
            # this fails.
            try {
                Start-Service -Name Netlogon
            } catch {
                Add-Warning -obj $result -message "Failed to start the Netlogon service after promoting the host, Ansible may be unable to connect until the host is manually rebooting: $($_.Exception.Message)"
            }
        }
    }
}

Exit-Json $result
