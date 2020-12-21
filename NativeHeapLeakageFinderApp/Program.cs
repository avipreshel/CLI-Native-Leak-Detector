using System;
using System.Linq;
using System.Diagnostics;
using Microsoft.Diagnostics.Tracing.Session;
using System.Threading;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace NativeHeapLeakageFinder
{
    class Program
    {
        static void Main(string[] args)
        {
            (IntPtr handle,int pid) = GetProcessHandles("CPPConsoleApp1");

            CancellationTokenSource cts = new CancellationTokenSource();

            ETWEventHandler evHandler = new ETWEventHandler(pid);
            evHandler.StartEventQueue(cts.Token); // Start a worker thread that shall handle incoming ETW events

            InitDbgHelp(pid, handle);

            // Cleanup old sessions
            foreach (var name in TraceEventSession.GetActiveSessionNames())
            {
                if (!name.Contains(Process.GetCurrentProcess().ProcessName))
                    continue;

                var session = TraceEventSession.GetActiveSession(name);
                Console.WriteLine($"removing session {name}");
                session.Stop(noThrow: true);
                session.Dispose();
            }
            Stopwatch watch = Stopwatch.StartNew();
            // Generating a new ETW session with a unique name for this process, so that we can easily find old sessions in the cleanup mechanism above
            string sessionName = Process.GetCurrentProcess().ProcessName + "_" + Guid.NewGuid().ToString();
            Console.WriteLine($"Starting ETW session: {sessionName}");
            using (var session = new TraceEventSession(sessionName))
            {
                Thread t = new Thread(() =>
               {
                   Console.ReadKey();
                   cts.Cancel();
                   session.Source.StopProcessing();
                   session.Dispose();
               }); t.Start();

                session.EnableWindowsHeapProvider(pid);
                session.Source.Dynamic.All += evHandler.HandleEvent; // this is for the stack trace
                session.Source.Kernel.All += evHandler.HandleEvent; // this is for the alloc/dealloc
                
                // iterate over the file, calling the callbacks.  
                
                session.Source.Process();
                session.Source.Dynamic.All -= evHandler.HandleEvent; // this is for the stack trace
                session.Source.Kernel.All -= evHandler.HandleEvent; // this is for the alloc/dealloc
            }
            watch.Stop();
            Console.WriteLine($"End of ETW session: {sessionName}");

            HelperClasses.PrintReport(handle, AllocationTracker.Suspects, watch, true);
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        static (IntPtr handle, int pid) GetProcessHandles(string processName)
        {
            var proc = Process.GetProcessesByName(processName).FirstOrDefault();
            if (proc == null)
            {
                throw new Exception($"Process {processName} not found");
            }

            var handle = UnsafeNativeMethods.OpenProcess(UnsafeNativeMethods.PROCESS_ALL_ACCESS, false, (uint)proc.Id);
            if (handle == IntPtr.Zero)
            {
                throw new Exception($"Failed to get handle to process {processName}");
            }

            return (handle, proc.Id);
        }

        

        static void InitDbgHelp(int pid,IntPtr handle)
        {
            bool ans = NativeDbgHelp.SymInitialize(handle, null, true);
            if (!ans)
            { 
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }
}
