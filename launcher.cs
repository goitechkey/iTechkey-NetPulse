// ============================================================================
//  iTechkey NetPulse — Native EXE Launcher
//  Version : 1.0.0
//  Author  : iTechkey
//  Contact : admin@itechkey.com
//
//  This launcher:
//  1. Locates install-windows.ps1 next to the .exe
//  2. Requests administrator elevation (UAC)
//  3. Runs PowerShell with ExecutionPolicy Bypass
//  4. Shows a professional console UI
//  5. Keeps the window open on error for debugging
// ============================================================================

using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Principal;
using System.Threading;

class iTechkeyLauncher
{
    const string APP_NAME    = "iTechkey NetPulse";
    const string APP_VERSION = "1.0.0";
    const string CONTACT     = "admin@itechkey.com";
    const string PS_SCRIPT   = "install-windows.ps1";

    static int Main(string[] args)
    {
        Console.Title = APP_NAME + " Installer";
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        PrintBanner();

        // --- Locate the folder where the .exe lives ---
        string exePath = Assembly.GetEntryAssembly().Location;
        string exeDir  = Path.GetDirectoryName(exePath);
        string psScript = Path.Combine(exeDir, PS_SCRIPT);

        Console.WriteLine("  [i] Installer folder : " + exeDir);
        Console.WriteLine("  [i] PowerShell script: " + PS_SCRIPT);
        Console.WriteLine();

        // --- Check script exists ---
        if (!File.Exists(psScript))
        {
            Error("Cannot find " + PS_SCRIPT + " next to this .exe.");
            Console.WriteLine();
            Console.WriteLine("  Expected location:");
            Console.WriteLine("    " + psScript);
            Console.WriteLine();
            Console.WriteLine("  Make sure the ZIP was extracted completely.");
            PauseOnExit();
            return 1;
        }

        // --- Check PowerShell availability ---
        if (!IsPowerShellAvailable())
        {
            Error("PowerShell is not available on this system.");
            Console.WriteLine("  This installer requires Windows 10 or later.");
            PauseOnExit();
            return 1;
        }

        // --- Elevate to Administrator if not already ---
        if (!IsAdministrator())
        {
            Console.WriteLine("  [!] Requesting administrator privileges...");
            Console.WriteLine("      (A UAC prompt will appear)");
            Console.WriteLine();
            try
            {
                return RunElevated(exePath, args);
            }
            catch (Exception ex)
            {
                Error("Failed to elevate: " + ex.Message);
                Console.WriteLine();
                Console.WriteLine("  You can also right-click this .exe and choose");
                Console.WriteLine("  'Run as administrator'.");
                PauseOnExit();
                return 1;
            }
        }

        Console.WriteLine("  [OK] Running with administrator privileges");
        Console.WriteLine();

        // --- Run PowerShell installer ---
        return RunPowerShell(psScript);
    }

    // ------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------
    static void PrintBanner()
    {
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.WriteLine();
        Console.WriteLine("  ====================================================");
        Console.WriteLine("    " + APP_NAME + " - Windows Installer");
        Console.WriteLine("    Version " + APP_VERSION);
        Console.WriteLine("    " + CONTACT);
        Console.WriteLine("  ====================================================");
        Console.ResetColor();
        Console.WriteLine();
    }

    static void Error(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("  [ERR] " + msg);
        Console.ResetColor();
    }

    static void Info(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  [i]   " + msg);
        Console.ResetColor();
    }

    static void PauseOnExit()
    {
        Console.WriteLine();
        Console.Write("  Press Enter to exit... ");
        Console.ReadLine();
    }

    static bool IsAdministrator()
    {
        try
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    static bool IsPowerShellAvailable()
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -Command \"exit 0\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true
            };
            using (Process p = Process.Start(psi))
            {
                p.WaitForExit(5000);
                return p.ExitCode == 0;
            }
        }
        catch
        {
            return false;
        }
    }

    static int RunElevated(string exePath, string[] args)
    {
        ProcessStartInfo psi = new ProcessStartInfo
        {
            FileName = exePath,
            UseShellExecute = true,
            Verb = "runas"   // UAC prompt
        };
        // preserve args
        if (args != null && args.Length > 0)
            psi.Arguments = string.Join(" ", args);

        try
        {
            Process p = Process.Start(psi);
            p.WaitForExit();
            return p.ExitCode;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // User cancelled UAC
            Console.WriteLine();
            Info("Elevation cancelled by user.");
            PauseOnExit();
            return 1;
        }
    }

    static int RunPowerShell(string psScript)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine();
        Console.WriteLine("  ====================================================");
        Console.WriteLine("   Launching PowerShell installer...");
        Console.WriteLine("  ====================================================");
        Console.ResetColor();
        Console.WriteLine();

        ProcessStartInfo psi = new ProcessStartInfo
        {
            FileName  = "powershell.exe",
            Arguments = "-NoProfile -ExecutionPolicy Bypass -NoExit -File \"" + psScript + "\"",
            UseShellExecute = false,
            WorkingDirectory = Path.GetDirectoryName(psScript)
        };

        try
        {
            Process p = Process.Start(psi);
            p.WaitForExit();

            Console.WriteLine();
            if (p.ExitCode == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  [OK] Installer completed successfully.");
                Console.ResetColor();
            }
            else
            {
                Error("Installer exited with code " + p.ExitCode);
            }

            PauseOnExit();
            return p.ExitCode;
        }
        catch (Exception ex)
        {
            Error("Failed to launch PowerShell: " + ex.Message);
            Console.WriteLine();
            Console.WriteLine("  Try running manually:");
            Console.WriteLine("    powershell -ExecutionPolicy Bypass -File \"" + psScript + "\"");
            PauseOnExit();
            return 1;
        }
    }
}