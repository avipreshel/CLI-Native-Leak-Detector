using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NativeHeapLeakageFinder
{
    public static class ExtensionMethods
    {
        /// <summary>
        /// A small helper extension method that let us conviniently extract the addresses from StackWalkStackTraceData class
        /// </summary>
        /// <param name="stackWalkEvent"></param>
        /// <returns></returns>
        static public ulong[] GetAddressesExt(this StackWalkStackTraceData stackWalkEvent)
        {
            ulong[] address = new ulong[stackWalkEvent.FrameCount];
            for (int i = 0; i < stackWalkEvent.FrameCount; i++)
            {
                address[i] = (ulong)stackWalkEvent.InstructionPointer(i);
            }
            return address;
        }
    }
}
