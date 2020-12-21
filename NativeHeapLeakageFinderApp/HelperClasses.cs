using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NativeHeapLeakageFinder
{
    public static class HelperClasses
    {
        /// <summary>
        /// A set of familiar system symbols that we can hide from the user (in case user turns on this feature)
        /// </summary>
        private static HashSet<string> SystemSymbols = new HashSet<string>()
        {
            "__scrt_common_main_seh",
            "BaseThreadInitThunk",
            "RtlUserThreadStart",
            "RtlAllocateHeap",
            "malloc_base",
            "operator new",
            "Wow64SystemServiceEx",
            "TurboDispatchJumpAddressEnd",
            "BTCpuSimulate",
            "Wow64LdrpInitialize",
            "LdrInitShimEngineDynamic",
            "memset",
            "LdrInitializeThunk",
            "calloc_base",
            "malloc_dbg",
            "malloc",
            "invoke_main",
            "mainCRTStartup",
            "__scrt_common_main",
            "ATL::",
            "atl::",
            "STD::",
            "std::",
            "SysAllocString",
            "SysAllocStringLen"
        };

        static (string symbolName,string fileName,uint codeLine) GetInfo(IntPtr handle, ulong address)
        {
            try
            {
                var symbol = SYMBOL_INFO.Create();
                if (NativeDbgHelp.SymFromAddr(handle, address, out var displacement, ref symbol))
                {

                    IMAGEHLP_LINE64 line = new IMAGEHLP_LINE64();
                    if (!NativeDbgHelp.SymGetLineFromAddr(handle, address, out var displacement2, ref line))
                    {
                        var err = Marshal.GetLastWin32Error();
                    }
                    return (symbolName :  symbol.Name, fileName : line.FileName, codeLine : line.LineNumber);
                }
            }
            catch (Exception)
            {
                return ("NaN", "NaN", 0); // pdb missing?
            }
            return ( string.Empty,string.Empty,0); // unknown case
        }

        public static void PrintReport(IntPtr handle,List<AllocSpot> suspects, Stopwatch elapsedTime, bool hideSystemStack)
        {
            int counter = 1;
            foreach (var allocSpot in suspects.OrderByDescending(allocSpot => allocSpot.OutstandingAllocations.Count))
            {
                int outStandingAllocationCount = allocSpot.OutstandingAllocations.Count();
                long outStandingAllocationBytes = allocSpot.OutstandingAllocations.Sum(item => (long)item.Value.ByteSize);
                Console.WriteLine("**********************************************************");
                Console.WriteLine($"Suspect call stack No.{counter}:");
                Console.WriteLine($"Total leakage [Bytes]: {outStandingAllocationBytes:n0}");// =  [Bytes] per object");
                float totalLeakMB = outStandingAllocationBytes / (1024f * 1024f);
                Console.WriteLine($"Total leakage [MBytes]: {totalLeakMB:F2}");
                Console.WriteLine($"Expected leakage [MBytes] per hour: {totalLeakMB / elapsedTime.Elapsed.TotalHours:F2}");
                Console.WriteLine($"Unallocated instance count: {outStandingAllocationCount:n0}");
                Console.WriteLine($"Leakage per instance [Bytes]: {outStandingAllocationBytes / outStandingAllocationCount}");
                
                Console.WriteLine("Call Stack:");
                foreach (ulong address in allocSpot.StackTrace)
                {
                    var symbolInfo = HelperClasses.GetInfo(handle, address);
                    bool isSystemSymbol = SystemSymbols.Any(item => symbolInfo.symbolName.Contains(item));

                    if (string.IsNullOrEmpty(symbolInfo.symbolName.Trim()))
                        continue;

                    if (isSystemSymbol && hideSystemStack)
                    {
                        continue;
                    }

                    if (!symbolInfo.symbolName.Contains("::"))
                    {
                        symbolInfo.symbolName = $"::{symbolInfo.symbolName}"; // Add "::" prefix, so that user will know it's a method
                    }

                    Console.WriteLine($"{symbolInfo.symbolName},{symbolInfo.fileName} : Line {symbolInfo.codeLine}");
                }
                counter++;
            }
        }
    }
}
