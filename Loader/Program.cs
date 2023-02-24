using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace Loader
{
    class Program
    {
        private static int ExecuteCommandSync(string bPath, string bCommand = null)
        {
            var bRet = -1;

            using (var cliProcess = new Process()
                   {
                       StartInfo = new ProcessStartInfo(bPath, bCommand)
                       {
                           UseShellExecute = false,
                           RedirectStandardOutput = true,
                           CreateNoWindow = true
                       },
                       EnableRaisingEvents = true
                   })
            {
                cliProcess.Start();
                cliProcess.WaitForExit();
                bRet = cliProcess.ExitCode;
                
                cliProcess.Close();
            }

            return bRet;
        }


        static void Main(string[] args)
        {
            var currentFolder = Directory.GetCurrentDirectory();
            var dataFolder = Path.Combine(currentFolder, "data");

            var driverPath = Path.Combine(dataFolder, "HypervisorHiderDrv.sys");
            var klhkDriverPath = Path.Combine(dataFolder, "klhk.sys");

            var kduFolder = Path.Combine(dataFolder, "kdu");
            var kduPath = Path.Combine(kduFolder, "kdu.exe");

            var klhkStatus = DriverInstaller.GetServiceStatus("klhk");

            if (klhkStatus == WinAPI.ServiceState.NotFound)
            {
                DriverInstaller.Install("klhk", "Kaspersky Lab service driver", klhkDriverPath);

                var reg = Registry.LocalMachine.CreateSubKey("System\\CurrentControlSet\\Services\\klhk\\Parameters");

                if (reg != null)
                {
                    reg.SetValue("UseHvm", 1);
                    Console.WriteLine("Regedit ok");
                }
                else
                    Console.WriteLine("Regedit failed");
            }
            
            if (klhkStatus != WinAPI.ServiceState.Running)
            {
                DriverInstaller.StartService("klhk");

                while (klhkStatus != WinAPI.ServiceState.Running)
                {
                    klhkStatus = DriverInstaller.GetServiceStatus("klhk");
                    Thread.Sleep(100);
                }
            }

            var driverStatus = DriverInstaller.GetServiceStatus("HypervisorHider");

            if (driverStatus == WinAPI.ServiceState.NotFound)
                DriverInstaller.Install("HypervisorHider", "HypervisorHider driver", driverPath);

            if (driverStatus != WinAPI.ServiceState.Running)
            {
                try
                {
                    var dwExitCode = ExecuteCommandSync(kduPath, "-dse 0");

                    if (dwExitCode == 1)
                        DriverInstaller.StartService("HypervisorHider");
                }
                finally
                {
                    ExecuteCommandSync(kduPath, "-dse 6");
                }

                while (driverStatus != WinAPI.ServiceState.Running)
                {
                    driverStatus = DriverInstaller.GetServiceStatus("HypervisorHider");
                    Thread.Sleep(100);
                }
            }

            Console.WriteLine($"klhk: {klhkStatus}");
            Console.WriteLine($"HypervisorHider: {driverStatus}");
            Console.Read();
        }
    }
}
