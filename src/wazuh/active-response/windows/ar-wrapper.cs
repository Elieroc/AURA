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

        // UNE ligne, pas ReadToEnd : le message AR tient sur une ligne, et
        // wazuh-execd NE FERME PAS notre stdin avant notre propre sortie. Avec
        // ReadToEnd, on attendait donc un EOF qui n'arrivait jamais pendant
        // qu'execd attendait notre sortie : interblocage. Le thread d'active
        // response de l'agent restant bloque derriere, TOUTES les remediations
        // suivantes s'empilaient sans jamais partir - elles ne se debloquaient
        // qu'au redemarrage du service, qui fermait le tube et liberait d'un
        // coup un wrapper vieux de plusieurs minutes. C'est ce qui faisait
        // croire a un simple "delai" de la remediation Windows.
        // Les scripts Linux ont toujours lu une seule ligne (`read -r`) : c'est
        // le contrat, et c'est la seule lecture qui rend la main.
        string input = Console.In.ReadLine();
        if (input == null) { input = ""; }

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
                // On ferme le tube apres ecriture : c'est NOUS qui donnons
                // l'EOF au script, ce qu'execd ne fait pas pour nous.
                p.StandardInput.WriteLine(input);
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
