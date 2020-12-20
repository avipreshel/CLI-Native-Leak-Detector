using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NativeHeapLeakageFinder
{
    public static class HelperClasses
    {
        private static HashSet<string> SystemSymbols = new HashSet<string>()
        {
            "__scrt_common_main_seh",
            "BaseThreadInitThunk",
            "RtlUserThreadStart",
            "RtlAllocateHeap",
            "malloc_base",
            "operator new"
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

        public static void PrintReport(IntPtr handle,List<AllocSpot> suspects,bool ignoreSystemStack)
        {
            int counter = 1;
            foreach (var allocSpot in suspects.OrderByDescending(allocSpot => allocSpot.OutstandingAllocations.Sum(item => (long)item.Value.ByteSize)))
            {
                int outStandingAllocationCount = allocSpot.OutstandingAllocations.Count();
                long outStandingAllocationBytes = allocSpot.OutstandingAllocations.Sum(item => (long)item.Value.ByteSize);
                Console.WriteLine($"Suspect #{counter}:");
                Console.WriteLine($"Unallocated objects: {outStandingAllocationCount}");
                Console.WriteLine($"Total leakage: {outStandingAllocationBytes} [Bytes] = {(ulong)(outStandingAllocationBytes / outStandingAllocationCount):n} [Bytes] per object");
                foreach (ulong address in allocSpot.StackTrace)
                {
                    var symbolInfo = HelperClasses.GetInfo(handle, address);
                    if (ignoreSystemStack && SystemSymbols.Contains(symbolInfo.symbolName))
                        continue; // ignore any C++ run time symbols. This is so that user can concentrace on the user code

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
