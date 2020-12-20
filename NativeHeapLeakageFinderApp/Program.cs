using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics.Contracts;
using System.Security.Cryptography;
using System.Diagnostics;
using System.IO;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using System.Threading;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Xml;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using System.ComponentModel;

namespace NativeHeapLeakageFinder
{
    class ETWEventHandler
    {
        int _pid;

        public ETWEventHandler(int pid)
        {
            _pid = pid;
        }

        public void HandleEvent(TraceEvent data)
        {
            if (data.ProcessID == _pid)
            {
                Program.s_eventQueue.Add(data.Clone());
            }
        }
    }

    class Program
    {
        public static BlockingCollection<TraceEvent> s_eventQueue = new BlockingCollection<TraceEvent>();
        static uint s_pid;

        static void Main(string[] args)
        {
            CheckPreConditions();

            (IntPtr handle,int pid) = GetProcessMetadata("CPPConsoleApp1");

            CancellationTokenSource cts = new CancellationTokenSource();

            StartEventQueue(cts.Token); // Start a worker thread that shall handle the ETW event queue

            ETWEventHandler evHandler = new ETWEventHandler(pid);

            s_pid = (uint)pid;
            
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

            // Generating a new ETW session with a unique name for this process, so that we can easily find old sessions in the cleanup mechanism above
            using (var session = new TraceEventSession(Process.GetCurrentProcess().ProcessName + "_" +  Guid.NewGuid().ToString()))
            {
                Thread t = new Thread(() =>
               {
                   Console.ReadKey();
                   Console.WriteLine("Stopping session");
                   cts.Cancel();
                   session.Source.StopProcessing();
                   session.Dispose();
               }); t.Start();

                
                session.EnableWindowsHeapProvider((int)s_pid);
                session.Source.Dynamic.All += evHandler.HandleEvent; // this is for the stack trace
                session.Source.Kernel.All += evHandler.HandleEvent; // this is for the alloc/dealloc
                
                // iterate over the file, calling the callbacks.  
                Console.WriteLine("Start session");
                session.Source.Process();
                session.Source.Dynamic.All -= evHandler.HandleEvent; // this is for the stack trace
                session.Source.Kernel.All -= evHandler.HandleEvent; // this is for the alloc/dealloc
            }

            Console.WriteLine("End session : Reporting");

            HelperClasses.PrintReport(handle, AllocationTracker.Suspects, true);
            Console.ReadKey();
        }

        static void CheckPreConditions()
        {
            if (TraceEventSession.IsElevated() != true)
            {
                throw new Exception("Please run again with elevated (Admin) permissions");
            }

            
        }

        static (IntPtr handle, int pid) GetProcessMetadata(string processName)
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

        static void StartEventQueue(CancellationToken cancelToken)
        {
            Thread eventListener = new Thread(() =>
            {
                do
                {
                    try
                    {


                        var eventItem = s_eventQueue.Take(cancelToken);
                        switch (eventItem.EventName)
                        {
                            case "Heap/Alloc":
                                var allocEvent = new HeapAllocationEvent()
                                {
                                    Address = (ulong)eventItem.PayloadByName("AllocAddress"),
                                    ByteSize = (ulong)eventItem.PayloadByName("AllocSize"),
                                    AllocEventId = eventItem.TimeStampRelativeMSec.ToString() // For some odd reason, this double value is the key to identify a stack event in StackWalkStackTraceData
                                };
                                AllocationTracker.OnAlloc(allocEvent);
                                break;
                            case "Heap/Free":
                                var deAllocEvent = new HeapDeAllocationEvent()
                                {
                                    Address = (ulong)eventItem.PayloadByName("FreeAddress")
                                };
                                AllocationTracker.OnDeAlloc(deAllocEvent);
                                break;
                            case "StackWalk/Stack":
                                var stackWalkEvent = eventItem as StackWalkStackTraceData;

                                var stackEvent = new StackTrackEvent()
                                {
                                    StackTrace = stackWalkEvent.GetAddressesExt(),
                                    AllocEventId = stackWalkEvent.EventTimeStampRelativeMSec.ToString()
                                };
                                AllocationTracker.OnStackEvent(stackEvent);
                                break;
                        }

                        AllocationTracker.Print();
                    }
                    catch (Exception)
                    {
                        break;
                    }
                } while (!cancelToken.IsCancellationRequested);
            });
            eventListener.Start();
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
