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
        private static readonly HashSet<string> KnownSystemSymbols = new HashSet<string>()
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
            "SysAllocStringLen",
            "C2VectParallel",
            "omp_get_wtick",
            "vcomp_fork",
            "vcomp_atomic_div_r8"
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

        public static void PrintReport(IntPtr handle,List<AllocSpot> suspects, Stopwatch elapsedTime, bool hideSystemStack, int topX, bool ignoreSingleAllocs)
        {
            int counter = 1;

            suspects = suspects.OrderByDescending(allocSpot => allocSpot.OutstandingAllocations.Count).ToList();

            if (ignoreSingleAllocs)
            {
                suspects = suspects.Where(item => item.OutstandingAllocations.Count > 1).ToList();
            }

            suspects = suspects.Take(topX).ToList();

            foreach (var allocSpot in suspects)
            {
                int outStandingAllocationCount = allocSpot.OutstandingAllocations.Count();
                long outStandingAllocationBytes = allocSpot.OutstandingAllocations.Sum(item => (long)item.Value.ByteSize);
                Console.WriteLine("**********************************************************");
                Console.WriteLine($"Suspect call stack No.{counter}:");
                Console.WriteLine($"Total leakage [Bytes]: {outStandingAllocationBytes:n0}");// =  [Bytes] per object");
                float totalLeakMB = outStandingAllocationBytes / (1024f * 1024f);
                Console.WriteLine($"Total leakage [MBytes]: {totalLeakMB:F2}");
                Console.WriteLine($"Estimated leakage over time [MBytes per hour]: {totalLeakMB / elapsedTime.Elapsed.TotalHours:F2}");
                Console.WriteLine($"Unallocated instance count: {outStandingAllocationCount:n0}");
                Console.WriteLine($"Leakage per instance [Bytes]: {outStandingAllocationBytes / outStandingAllocationCount}");
                
                Console.WriteLine("Call Stack:");
                foreach (ulong address in allocSpot.StackTrace)
                {
                    var (symbolName, fileName, codeLine) = HelperClasses.GetInfo(handle, address);
                    bool isSystemSymbol = KnownSystemSymbols.Any(item => symbolName.Contains(item));

                    if (string.IsNullOrEmpty(symbolName.Trim()))
                        continue;

                    if (isSystemSymbol && hideSystemStack)
                    {
                        continue;
                    }

                    if (!symbolName.Contains("::"))
                    {
                        symbolName = $"::{symbolName}"; // Add "::" prefix, so that user will know it's a method
                    }

                    Console.WriteLine($"{symbolName},{fileName} : Line {codeLine}");
                }
                counter++;
            }
        }
    }
}
