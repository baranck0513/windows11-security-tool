import subprocess
import json
from datetime import datetime
import sys

class SecurityScanner:
    def __init__(self): # initialsing
        pass
    
    def run_powershell(self, command):
        # to execute powershell commands and returns the result
        try:
            result = subprocess.run(
                ["powershell", "-Command", command],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout.strip(), result.returncode == 0
        except Exception as e:
            return f"Error: {str(e)}", False
    
    def check_antivirus(self):
        # Checks antivirus status (Windows Defender or user's anti virus)
        print("Checking Antivirus status")
        
        # checking all the anti virus products from windows security center
        command = """
        $antivirusProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
        if ($antivirusProducts) {
            $antivirusProducts | Select-Object displayName, productState | ConvertTo-Json
        } else {
            # If SecurityCenter2 doesn't work, check Windows Defender
            $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($defender) {
                @{
                    displayName = "Windows Defender"
                    AntivirusEnabled = $defender.AntivirusEnabled
                    RealTimeProtectionEnabled = $defender.RealTimeProtectionEnabled
                } | ConvertTo-Json
            } else {
                "NO_AV_FOUND"
            }
        }
        """
        
        output, success = self.run_powershell(command)
        
        if success and output and output != "NO_AV_FOUND":
            try:
                data = json.loads(output)
                
                # making it a list
                if isinstance(data, dict):
                    data = [data]
                
                av_list = []
                active_av = None
                
                for av in data:
                    if 'displayName' in av:
                        av_name = av['displayName']
                        
                        # for user's own anti virus
                        if 'productState' in av:
                            # productState's last byte indicates status
                            # active: 266240, 266256, 397312, etc.
                            state = av['productState']
                            # large numbers usually mean active
                            is_active = state > 200000
                            
                            if is_active:
                                active_av = av_name
                                av_list.append(f"{av_name} (Active)")
                            else:
                                av_list.append(f"{av_name} (Inactive)")
                        else:
                            # windows defender
                            if av.get('AntivirusEnabled') and av.get('RealTimeProtectionEnabled'):
                                active_av = av_name
                                av_list.append(f"{av_name} (Active)")
                            else:
                                av_list.append(f"{av_name} (Inactive)")
                
                if active_av:
                    print(f"Status: PASS")
                    print(f"Active Antivirus: {active_av}")
                    print(f"All Detected: {', '.join(av_list)}")
                    print(f"{active_av} is protecting your system")
                else:
                    print(f"Status: FAIL")
                    print(f"Active Antivirus: None")
                    print(f"Detected Products: {', '.join(av_list) if av_list else 'None'}")
                    print("No active antivirus detected")
            except Exception as e:
                print(f"Status: ERROR")
                print(f"Could not parse antivirus data: {str(e)}")
                print("Manually check Windows Security settings")
        else:
            print(f"Status: ERROR")
            print("Could not retrieve antivirus information")
            print("Ensure you have administrator privileges and try again")
    
    def check_firewall(self):
        # checks if firewall is enabled or disabled
        print("Checking Firewall status")
        command = "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
        output, success = self.run_powershell(command)
        
        if success and output:
            try:
                data = json.loads(output)
                if isinstance(data, dict):
                    data = [data]
                
                enabled_profiles = []
                disabled_profiles = []
                
                for profile in data:
                    profile_name = profile.get('Name', 'Unknown')
                    if profile.get('Enabled', False):
                        enabled_profiles.append(profile_name)
                    else:
                        disabled_profiles.append(profile_name)
                
                if len(enabled_profiles) == len(data):
                    # all profiles enabled
                    print(f"Status: PASS")
                    print(f"Firewall Status: All profiles enabled")
                    print(f"Enabled Profiles: {', '.join(enabled_profiles)}")
                    print("Firewall is properly configured")
                elif len(enabled_profiles) > 0:
                    # some profiles enabled, some disabled
                    print(f"Status: WARN")
                    print(f"Firewall Status: Partially enabled")
                    print(f"Enabled: {', '.join(enabled_profiles)}")
                    print(f"Disabled: {', '.join(disabled_profiles)}")
                    print(f'Enable firewall for all profiles. Currently disabled: {", ".join(disabled_profiles)}')
                else:
                    # all profiles disabled
                    print(f"Status: FAIL")
                    print(f"Firewall Status: All profiles disabled")
                    print(f"Disabled Profiles: {', '.join(disabled_profiles)}")
                    print("Windows Firewall is disabled")
            except Exception as e:
                print(f"Status: ERROR")
                print(f"Could not parse firewall data: {str(e)}")
                print("Manually check Firewall settings")
        else:
            print(f"Status: ERROR")
            print("Could not retrieve firewall status")
            print("Ensure you have administrator privileges")
    
    def check_user_password(self):
        # checks if the user has a password or PIN configured
        print("Checking user password/PIN status")
        
        # get current user information and check password status
        command = """
        $currentUser = $env:USERNAME
        $user = Get-LocalUser -Name $currentUser -ErrorAction SilentlyContinue
        
        if ($user) {
            # Check if password is required
            $passwordRequired = -not $user.PasswordRequired
            
            # Check for PIN existence (Windows Hello)
            $pinExists = $false
            try {
                $ngc = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{D6886603-9D2F-4EB2-B667-1971041FA96B}" -ErrorAction SilentlyContinue
                if ($ngc) {
                    $pinExists = $true
                }
            } catch {}
            
            # Password last set date
            $passwordLastSet = $user.PasswordLastSet
            $passwordNeverExpires = $user.PasswordNeverExpires
            
            @{
                Username = $currentUser
                PasswordRequired = $user.PasswordRequired
                PasswordLastSet = if ($passwordLastSet) { $passwordLastSet.ToString() } else { "Never" }
                PasswordNeverExpires = $passwordNeverExpires
                Enabled = $user.Enabled
            } | ConvertTo-Json
        } else {
            "USER_NOT_FOUND"
        }
        """
        
        output, success = self.run_powershell(command)
        
        if success and output and output != "USER_NOT_FOUND":
            try:
                data = json.loads(output)
                
                username = data.get('Username', 'Unknown')
                password_required = data.get('PasswordRequired', False)
                password_last_set = data.get('PasswordLastSet', 'Never')
                
                if password_required and password_last_set != "Never":
                    print(f"Status: PASS")
                    print(f"Username: {username}")
                    print(f"Password Status: Password is set")
                    print("Device is protected with a password")
                elif password_required and password_last_set == "Never":
                    print(f"Status: WARN")
                    print(f"Username: {username}")
                    print(f"Password Status: Password required but never set")
                    print("Set a strong password")
                else:
                    print(f"Status: FAIL")
                    print(f"Username: {username}")
                    print(f"Password Status: No password set")
                    print("No password detected")
            except Exception as e:
                print(f"Status: ERROR")
                print(f"Could not parse user data: {str(e)}")
                print("Manually check account settings")
        else:
            print(f"Status: ERROR")
            print("Could not retrieve user account information")
            print("Ensure you have administrator privileges")

    def check_windows_update(self):
        # checks if automatic windows updates are enabled
        print("Checking Windows Update settings")

        command = """
        $updateService = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" -ErrorAction SilentlyContinue
        
        if ($updateService) {
            $noAutoUpdate = $updateService.NoAutoUpdate
            $auOptions = $updateService.AUOptions
            
            @{
                NoAutoUpdate = $noAutoUpdate
                AUOptions = $auOptions
            } | ConvertTo-Json
        } else {
            # check alternative registry location
            $updateService2 = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update" -ErrorAction SilentlyContinue
            
            if ($updateService2) {
                @{
                    NoAutoUpdate = $updateService2.AUOptions -eq 1
                    AUOptions = $updateService2.AUOptions
                } | ConvertTo-Json
            } else {
                # default Windows 10/11 behavior - check Windows Update service
                $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
                if ($wuService) {
                    @{
                        ServiceStatus = $wuService.Status
                        ServiceStartType = $wuService.StartType
                    } | ConvertTo-Json
                } else {
                    "NO_UPDATE_INFO"
                }
            }
        }
        """

        output, success = self.run_powershell(command)

        if success and output and output != "NO_UPDATE_INFO":
            try:
                data = json.loads(output)

                # check if updates are disabled
                if 'NoAutoUpdate' in data:
                    no_auto_update = data.get('NoAutoUpdate', 0)
                    au_options = data.get('AUOptions', 4)

                    # NoAutoUpdate = 1 means disabled, 0 means enabled
                    # AUOptions: 2 = notify, 3 = auto download, 4 = auto install

                    if no_auto_update == 1 or no_auto_update == True:
                        print(f"Status: FAIL")
                        print(f"Update Status: Automatic updates are disabled")
                        print("Enable automatic Windows updates in Settings")
                    elif au_options == 4 or au_options == 3:
                        print(f"Status: PASS")
                        print(f"Update Status: Automatic updates are enabled")
                        print("Windows updates are configured correctly")
                    elif au_options == 2:
                        print(f"Status: WARN")
                        print(f"Update Status: Updates notify only")
                        print("Change setting to automatically install updates")
                    else:
                        print(f"Status: WARN")
                        print(f"Update Status: Unknown configuration")
                        print("Verify Windows Update settings manually")

                elif 'ServiceStatus' in data:
                    # check service status
                    service_status = data.get('ServiceStatus', 'Unknown')
                    service_start = data.get('ServiceStartType', 'Unknown')

                    if service_status == "Running" and (service_start == "Automatic" or service_start == "Manual"):
                        print(f"Status: PASS")
                        print(f"Update Service: Running ({service_start})")
                        print("Windows Update service is active")
                    else:
                        print(f"Status: FAIL")
                        print(f"Update Service: {service_status} ({service_start})")
                        print("Windows Update service is not running properly")
                else:
                    print(f"Status: WARN")
                    print("Could not determine automatic update status")
                    print("Check Settings > Update & Security > Windows Update")
                    
            except Exception as e:
                print(f"Status: ERROR")
                print(f"Could not parse update data: {str(e)}")
                print("Manually check Windows Update settings")
        else:
            print(f"Status: WARN")
            print("Could not retrieve Windows Update information")
            print("Check Settings > Update & Security > Windows Update")

    def check_uac(self):
        # checking if UAC is set to maximum (always notify)
        print("Checking UAC settings")
        
        command = """
        $uacRegistry = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -ErrorAction SilentlyContinue
        
        if ($uacRegistry) {
            @{
                EnableLUA = $uacRegistry.EnableLUA
                ConsentPromptBehaviorAdmin = $uacRegistry.ConsentPromptBehaviorAdmin
                PromptOnSecureDesktop = $uacRegistry.PromptOnSecureDesktop
            } | ConvertTo-Json
        } else {
            "NO_UAC_INFO"
        }
        """
        
        output, success = self.run_powershell(command)
        
        if success and output and output != "NO_UAC_INFO":
            try:
                data = json.loads(output)
                
                enable_lua = data.get('EnableLUA', 0)
                consent_prompt = data.get('ConsentPromptBehaviorAdmin', 5)
                secure_desktop = data.get('PromptOnSecureDesktop', 1)
                
                # EnableLUA = 1 means UAC is enabled 
                # EnableLUA = 0 means UAC is disabled

                # ConsentPromptBehaviorAdmin values:
                # 0 = Elevate without prompting (worst)
                # 1 = Prompt for credentials on secure desktop (good - but not maximum)
                # 2 = Always notify (maximum security - best)
                # 3 = Prompt for credentials (medium)
                # 4 = Prompt for consent (medium)
                # 5 = Prompt for consent for non-Windows binaries (default)
                
                if enable_lua == 0:
                    print(f"Status: FAIL")
                    print(f"UAC Status: Disabled")
                    print("Enable UAC in System Settings")
                elif (consent_prompt == 2 or consent_prompt == 1) and secure_desktop == 1:
                    # Level 1 with secure desktop is actually the top setting
                    print(f"Status: PASS")
                    print(f"UAC Level: Always notify (Maximum)")
                    print("UAC is configured for maximum security")
                elif consent_prompt == 5 and secure_desktop == 1:
                    print(f"Status: WARN")
                    print(f"UAC Level: Default (recommended by Microsoft)")
                    print("Consider setting UAC to 'Always notify' for maximum security")
                elif consent_prompt == 5 and secure_desktop == 0:
                    print(f"Status: WARN")
                    print(f"UAC Level: Notify without secure desktop")
                    print("Increase UAC level for better security")
                elif consent_prompt == 0:
                    print(f"Status: FAIL")
                    print(f"UAC Level: Never notify")
                    print("UAC is effectively disabled")
                else:
                    print(f"Status: WARN")
                    print(f"UAC Level: Custom configuration")
                    print("Verify UAC settings in Control Panel")
                    
            except Exception as e:
                print(f"Status: ERROR")
                print(f"Could not parse UAC data: {str(e)}")
                print("Manually check UAC settings in Control Panel")
        else:
            print(f"Status: ERROR")
            print("Could not retrieve UAC information")
            print("Check User Account Control Settings in Control Panel")
        
    def run_scan(self, scan_type="Full Scan"):
        if scan_type == "Full Scan":        
            self.check_antivirus()
            print()
            self.check_firewall()
            print()
            self.check_user_password()
            print()
            self.check_windows_update()
            print()
            self.check_uac()
        elif scan_type == "Antivirus":
            self.check_antivirus()
        elif scan_type == "Firewall":
            self.check_firewall()
        elif scan_type == "Password":
            self.check_user_password()
        elif scan_type == "Windows Update":
            self.check_windows_update()
        elif scan_type == "User Account Control":
            self.check_uac()
        else:
            print(f"Unknown scan type: {scan_type}")


def main():
    if len(sys.argv) > 1:
        scan_type = sys.argv[1]
    else:
        scan_type = "Full Scan"        
    # create and run scanner
    scanner = SecurityScanner()
    
    # start the scan
    scanner.run_scan(scan_type)


if __name__ == "__main__":
    main()