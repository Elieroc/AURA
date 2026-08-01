// Generic Wazuh Windows active-response wrapper (compiled to a real .exe).
//
// wazuh-execd on Windows launches the registered <executable> with a raw
// CreateProcess, which can only start a genuine .exe — a .ps1 or .cmd fails with
// "(1317): Could not launch command". So each action ships as a real <action>.exe
// (a copy of this compiled wrapper) sitting next to <action>.ps1. The wrapper
// reads the AR JSON from its stdin and forwards it, unchanged, to
//     powershell.exe -File <action>.ps1
// so the PowerShell logic keeps the exact same stdin contract as the Linux AR.
//
// One binary serves every action: it derives the .ps1 name from its own path,
// so deployment just copies ar-wrapper.exe to win-block-ip.exe, ad-disable-account.exe, ...
//
// Build (no SDK needed; csc ships with the .NET Framework on every Windows host):
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /target:exe ^
//       /out:ar-wrapper.exe ar-wrapper.cs
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

class ArWrapper
{
    static int Main()
    {
        string exePath = Assembly.GetExecutingAssembly().Location;
        string ps1Path = Path.ChangeExtension(exePath, ".ps1");
        string input = Console.In.ReadToEnd();

        var psi = new ProcessStartInfo("powershell.exe",
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + ps1Path + "\"")
        {
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        try
        {
            using (var p = Process.Start(psi))
            {
                p.StandardInput.Write(input);
                p.StandardInput.Close();
                p.WaitForExit();
                return p.ExitCode;
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("ar-wrapper: " + e.Message);
            return 1;
        }
    }
}
