using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace NativeHeapLeakageFinder
{
    public class AllocSpot
    {
        public ulong[] StackTrace { get; set; }
        public ulong AllocTimes { get; set; }
        public Dictionary<ulong, HeapAllocationEvent> OutstandingAllocations { get; set; }
    }

    /// <summary>
    /// This needs to be a class since StackTraceHash is getting assigned to during run
    /// </summary>
    public class HeapAllocationEvent 
    {
        public string StackTraceHash { get; set; } = string.Empty;
        public string AllocEventId { get; set; }
        public ulong Address { get; set; }
        public ulong ByteSize { get; set; }
        public override string ToString()
        {
            return $"HeapAllocationEvent: {AllocEventId},{Address},{ByteSize}";
        }
    }

    public struct HeapDeAllocationEvent
    {
        public ulong Address { get; set; }
        public override string ToString()
        {
            return $"HeapDeAllocationEvent: {Address}";
        }
    }

    public struct StackTrackEvent
    {
        public string AllocEventId { get; set; }
        public ulong[] StackTrace { get; set; }
        public override string ToString()
        {
            return $"StackTrackEvent: {AllocEventId}";
        }
    }

    public static class AllocationTracker
    {
        static Dictionary<string, AllocSpot> MapHashToAllotSpot { get; set; } = new Dictionary<string, AllocSpot>();
        static List<HeapDeAllocationEvent> OutstandingDeallocations { get; set; } = new List<HeapDeAllocationEvent>(); // in case that de-allocation event has reached before AllocSpot was created

        static Dictionary<ulong, HeapAllocationEvent> OutstandingAllocations { get; set; } = new Dictionary<ulong, HeapAllocationEvent>();
        static Dictionary<string, HeapAllocationEvent> AllocEventIdToAllocEvent { get; set; } = new Dictionary<string, HeapAllocationEvent>();

        public static List<AllocSpot> Suspects => MapHashToAllotSpot.Values.ToList();

        static SHA256 SHA256Instance = SHA256.Create();

        static AllocationTracker()
        {

        }

        /// <summary>
        /// Use for NUnit purpose
        /// </summary>
        /// <returns></returns>
        public static bool IsEmpty()
        {
            return (AllocationTracker.MapHashToAllotSpot.Count == 0 &&
                    AllocationTracker.AllocEventIdToAllocEvent.Count == 0 && 
                    AllocationTracker.OutstandingAllocations.Count == 0 &&
                    AllocationTracker.OutstandingDeallocations.Count == 0);
        }

        public static void OnAlloc(HeapAllocationEvent ev)
        {
            OutstandingAllocations.Add(ev.Address, ev);
            AllocEventIdToAllocEvent.Add(ev.AllocEventId, ev);
        }

        public static void OnDeAlloc(HeapDeAllocationEvent ev)
        {
            // Console.WriteLine(ev);
            OutstandingDeallocations.Add(ev);

            HandleOutstandingEvents();
            CleanupHealthySpots();
        }

        public static void HandleOutstandingEvents()
        {
            var outstandingAllocs = OutstandingAllocations.Keys.ToList();
            foreach (var allocAddress in outstandingAllocs)
            {
                var allocEvent = OutstandingAllocations[allocAddress];
                if (MapHashToAllotSpot.TryGetValue(allocEvent.StackTraceHash, out AllocSpot allocSpot))
                {
                    allocSpot.OutstandingAllocations.Add(allocAddress, allocEvent);
                    OutstandingAllocations.Remove(allocAddress);
                }
            }

            var deadOnes = new List<HeapDeAllocationEvent>();
            foreach (var deallocEvent in OutstandingDeallocations)
            {
                foreach (var allocSpot in MapHashToAllotSpot)
                {
                    if (allocSpot.Value.OutstandingAllocations.TryGetValue(deallocEvent.Address, out HeapAllocationEvent allocEvent))
                    {
                        allocSpot.Value.OutstandingAllocations.Remove(deallocEvent.Address);
                        deadOnes.Add(deallocEvent);
                    }
                }
            }

            foreach (var dealloc in deadOnes)
            {
                OutstandingDeallocations.Remove(dealloc);
            }

        }

        /// <summary>
        /// Cleanup any spot which does not have any outstanding memory allocations
        /// </summary>
        public static void CleanupHealthySpots()
        {
            // Find if any allocation spot has no outstanding allocations
            List<string> spotsToDelete = new List<string>(MapHashToAllotSpot.Count);
            foreach (var allocSpot in MapHashToAllotSpot)
            {
                bool hasAnyOutstanding = allocSpot.Value.OutstandingAllocations.Any(item => item.Value.ByteSize > 0);
                if (!hasAnyOutstanding)
                {
                    spotsToDelete.Add(allocSpot.Key);
                }
            }

            foreach (var hashKey in spotsToDelete)
            {

                MapHashToAllotSpot.Remove(hashKey);
            }
        }

        public static void OnStackEvent(StackTrackEvent ev)
        {
            //onsole.WriteLine(ev);

            if (AllocEventIdToAllocEvent.TryGetValue(ev.AllocEventId, out HeapAllocationEvent allocEv))
            {
                AllocEventIdToAllocEvent.Remove(ev.AllocEventId); // We don't need this mapping anymore

                // A heap allocation spot can be uniquly identified by it's stack trace addresses. The following lines of code are converting
                // the stack trace memory addresses to a unique Base64 string, so that we can easily use it as a key in our map
                var callStackStr = ev.StackTrace.Select(item => item.ToString()).Aggregate((x, y) => $"{x},{y}");
                var stackHashKey = Convert.ToBase64String(SHA256Instance.ComputeHash(Encoding.Default.GetBytes(callStackStr)));
                OutstandingAllocations[allocEv.Address].StackTraceHash = stackHashKey; // Assign the stack hash key to the allocation object
                AllocSpot allocSpot = null;
                if (MapHashToAllotSpot.TryGetValue(stackHashKey, out allocSpot))
                {

                }
                else
                {
                    allocSpot = new AllocSpot()
                    {
                        StackTrace = ev.StackTrace,
                        OutstandingAllocations = new Dictionary<ulong, HeapAllocationEvent>()
                    };
                    MapHashToAllotSpot.Add(stackHashKey, allocSpot);
                }
                allocSpot.AllocTimes++;

            }
            else
            {
                // stack trace arrived for an allocation event which was not registred via OnAlloc() 
                // This can happen in case that the process was allocating events before the session has started
            }

            HandleOutstandingEvents();
            CleanupHealthySpots();
        }

        public static void Print()
        {
            foreach (var allocSpot in MapHashToAllotSpot)
            {
                Console.WriteLine($"{allocSpot.Key} allocated {allocSpot.Value.AllocTimes} times with total {allocSpot.Value.OutstandingAllocations.Count} outstanding allocations");
            }
        }
    }

}
