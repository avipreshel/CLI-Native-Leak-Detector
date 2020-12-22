using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NativeHeapLeakageFinder
{
    static class ETWEventOpcodes
    {
        public const int CallStack = 32;
        public const int Alloc = 33;
        public const int DeAlloc = 36;
    }

    class ETWEventHandler
    {
        readonly BlockingCollection<TraceEvent> s_eventQueue = new BlockingCollection<TraceEvent>();
        readonly int _pid;

        /// <summary>
        /// The pid acts as a filter. Any ETW event which is not related to the process we are tracking, will be ignored
        /// </summary>
        /// <param name="pid"></param>
        public ETWEventHandler(int pid)
        {
            _pid = pid;
        }

        /// <summary>
        /// This is the event handler callback. ETW framework calls this method, and we should return the call as fast as possible
        /// Also, we want to ignore any events which are unrelated to the process that we are tracking
        /// </summary>
        /// <param name="data"></param>
        public void HandleEvent(TraceEvent data)
        {
            if (data.ProcessID == _pid)
            {
                s_eventQueue.Add(data.Clone());
            }
        }

        /// <summary>
        /// Starts the event listener thread.
        /// This thread takes a single message from the queue, converts it to an internal event data structure with the bare minimum info that we need, and pass it on to the AllocationTracker
        /// </summary>
        /// <param name="cancelToken"></param>
        public void StartEventQueue(CancellationToken cancelToken)
        {
            Thread eventListener = new Thread(() =>
            {
                do
                {
                    try
                    {


                        var eventItem = s_eventQueue.Take(cancelToken);
                        switch ((int)(eventItem.Opcode))
                        {
                            case ETWEventOpcodes.Alloc:
                                var allocEvent = new HeapAllocationEvent()
                                {
                                    Address = (ulong)eventItem.PayloadByName("AllocAddress"),
                                    ByteSize = (ulong)eventItem.PayloadByName("AllocSize"),
                                    AllocEventId = eventItem.TimeStampRelativeMSec.ToString() // For some odd reason, this double value is the key to identify a stack event in StackWalkStackTraceData
                                };
                                AllocationTracker.OnAlloc(allocEvent);
                                break;
                            case ETWEventOpcodes.DeAlloc:
                                var deAllocEvent = new HeapDeAllocationEvent()
                                {
                                    Address = (ulong)eventItem.PayloadByName("FreeAddress")
                                };
                                AllocationTracker.OnDeAlloc(deAllocEvent);
                                break;
                            case ETWEventOpcodes.CallStack:
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
    }
}
