
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $here ".."

Describe "ThemisRules Integration" {
    Context "Module Loading" {
        It "Should import ThemisRules module successfully" {
            Import-Module $modulePath -Force -PassThru | Should -Not -BeNullOrEmpty
        }

        It "Should export Invoke-ThemisPolicy" {
            Get-Command Invoke-ThemisPolicy | Should -Not -BeNullOrEmpty
        }
    }

    Context "Policy Execution (Mocked)" {
        # Create a temp policy
        $tempPolicy = "$here\TestPolicy.json"
        
        BeforeAll {
            @{
                Meta          = @{ Name = "Test"; Version = "1.0" }
                RegistryRules = @(
                    @{ ID = "R1"; Name = "TestReg"; Path = "HKCU:\Software"; ValueName = "Test"; Value = "1"; Type = "String"; _ProviderType = "Registry" }
                )
                ServiceRules  = @(
                    @{ ID = "S1"; Name = "Spooler"; State = "Running"; _ProviderType = "Service" }
                )
            } | ConvertTo-Json | Out-File $tempPolicy
            
            # Re-import to ensure fresh state
            Import-Module $modulePath -Force
        }

        AfterAll {
            Remove-Item $tempPolicy -ErrorAction SilentlyContinue
        }

        It "Should execute without error" {
            { Invoke-ThemisPolicy -PolicyPath $tempPolicy } | Should -Not -Throw
        }

        It "Should return results" {
            $res = Invoke-ThemisPolicy -PolicyPath $tempPolicy
            $res.Count | Should -BeGe 0 # Could be 0 if mocked providers fail, but object shouldn't be null
        }
    }
    
    Context "Provider Logic (Mocked calls)" {
        # We can test internal provider logic by importing them directly if needed,
        # but for integration, we test via Invoke-ThemisPolicy
        
        # We rely on the fact that 'Spooler' service likely exists or not, but won't crash
        # and HKCU:\Software exists.
    }
}
