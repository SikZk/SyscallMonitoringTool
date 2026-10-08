rule SUSP_PowerShell_InMemory_DownloadCradle
{
    meta:
        author      = "SyscallMonitoringTool"
        description = "Download cradle or in-memory loader staged in a PowerShell process"
        reference   = "https://attack.mitre.org/techniques/T1059/001/"
        date        = "2026-10-08"

    strings:
        // PowerShell holds script text as UTF-16, so 'wide' is what actually
        // matches here; 'ascii' covers the same bytes arriving over a pipe or
        // sitting in a managed string that was marshalled down.
        $iex1 = "Invoke-Expression" ascii wide nocase
        $iex2 = "IEX(" ascii wide nocase
        $iex3 = "IEX (" ascii wide nocase

        $net1 = "Net.WebClient" ascii wide nocase
        $net2 = "DownloadString" ascii wide nocase
        $net3 = "DownloadData" ascii wide nocase
        $net4 = "Invoke-WebRequest" ascii wide nocase

        $mem1 = "FromBase64String" ascii wide nocase
        $mem2 = "Reflection.Assembly" ascii wide nocase
        $mem3 = "[Convert]::FromBase64String" ascii wide nocase

    condition:
        // An invocation primitive plus a way to fetch or decode the payload.
        // Either half alone is far too common in legitimate scripts.
        1 of ($iex*) and 1 of ($net*, $mem*)
}
