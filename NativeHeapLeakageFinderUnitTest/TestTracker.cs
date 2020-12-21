using Microsoft.VisualStudio.TestTools.UnitTesting;
using NativeHeapLeakageFinder;
using System;

namespace NativeHeapLeakageFinderUnitTest
{
    [TestClass]
    public class TestTracker
    {
        [TestMethod]
        public void Test_Alloc_Stack_Dealloc()
        {
            AllocationTracker.OnAlloc(new HeapAllocationEvent() { Address = 100, AllocEventId = "123.45", ByteSize = 4 });
            AllocationTracker.OnAlloc(new HeapAllocationEvent() { Address = 200, AllocEventId = "123.46", ByteSize = 4 });
            AllocationTracker.OnStackEvent(new StackTrackEvent() { AllocEventId = "123.45", StackTrace = new ulong[1] { 0 } });
            AllocationTracker.OnStackEvent(new StackTrackEvent() { AllocEventId = "123.46", StackTrace = new ulong[1] { 0 } });
            AllocationTracker.OnDeAlloc(new HeapDeAllocationEvent() { Address = 100 });
            AllocationTracker.OnDeAlloc(new HeapDeAllocationEvent() { Address = 200 });
            Assert.IsTrue(AllocationTracker.IsEmpty());
        }

        [TestMethod]
        public void Test_Alloc_Dealloc_Stack()
        {
            AllocationTracker.OnAlloc(new HeapAllocationEvent() { Address = 100, AllocEventId = "123.45", ByteSize = 4 });
            AllocationTracker.OnAlloc(new HeapAllocationEvent() { Address = 200, AllocEventId = "123.46", ByteSize = 4 });
            AllocationTracker.OnDeAlloc(new HeapDeAllocationEvent() { Address = 100 });
            AllocationTracker.OnDeAlloc(new HeapDeAllocationEvent() { Address = 200 });
            AllocationTracker.OnStackEvent(new StackTrackEvent() { AllocEventId = "123.45", StackTrace = new ulong[1] { 0 } });
            AllocationTracker.OnStackEvent(new StackTrackEvent() { AllocEventId = "123.46", StackTrace = new ulong[1] { 0 } });
            Assert.IsTrue(AllocationTracker.IsEmpty());
        }
    }
}
