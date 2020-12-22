using System;
using System.Linq;
using System.Diagnostics;
using Microsoft.Diagnostics.Tracing.Session;
using System.Threading;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Collections.Generic;

namespace NativeHeapLeakageFinder
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args == null || args.Length == 0)
            {
                Console.WriteLine("Input is missing parameters. Help:");
                Console.WriteLine("NativeHeapLeakageFinder.exe Myprocess -HideSystemStack -top:10");
                Console.WriteLine("-HideSystemStack option will hide any system symbols from call stack, making it easier to see the user code");
                Console.WriteLine("-top:xx option will show only the top xx results, where xx can by any number");
                Console.WriteLine("All options are not case sensitive :)");
                return;
            }

            (IntPtr handle, int pid) = GetProcessHandles("CPPConsoleApp1");

            (var processName, var topX, var hideSystemStack) = GetCommandLinePrms(args);

            CancellationTokenSource cts = new CancellationTokenSource();

            ETWEventHandler evHandler = new ETWEventHandler(pid);
            evHandler.StartEventQueue(cts.Token); // Start a worker thread that shall handle incoming ETW events

            InitDbgHelp(handle);

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

            HelperClasses.PrintReport(handle, AllocationTracker.Suspects, watch, hideSystemStack, topX);
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        static (string processName, int topX, bool hideSystemStack) GetCommandLinePrms(string[] args)
        {
            string processName = args[0].Replace(".exe", string.Empty);

            (IntPtr handle, int pid) = GetProcessHandles(processName);

            HashSet<string> options = new HashSet<string>(args.Skip(1).Select(item => item.ToLower()));

            bool hideSystemStack = options.Contains("-hidesystemstack");

            int topX = int.MaxValue;
            string topXStr = string.Empty;
            try
            {
                topXStr = options.FirstOrDefault(item => item.Contains("-top:"));
                topX = topXStr == null ? int.MaxValue : int.Parse(topXStr.Split(':')[1]);
            }
            catch (Exception)
            {
                throw new Exception($"{topXStr} contains a non-int value [{topXStr.Split(':')[1]}]");
            }

            return (processName, topX, hideSystemStack);
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

        static void InitDbgHelp(IntPtr handle)
        {
            bool ans = NativeDbgHelp.SymInitialize(handle, null, true);
            if (!ans)
            { 
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }
}
