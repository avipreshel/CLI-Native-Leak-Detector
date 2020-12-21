using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NativeHeapLeakageFinder
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SYMBOL_INFO
    {
        public uint SizeOfStruct;
        public uint TypeIndex;      // Type Index of symbol
        private ulong Reserved1;
        private ulong Reserved2;
        public uint Index;
        public uint Size;
        public ulong ModBase;       // Base Address of module containing this symbol
        public uint Flags;
        public ulong Value;         // Value of symbol, ValuePresent should be 1
        public ulong Address;       // Address of symbol including base address of module
        public uint Register;       // register holding value or pointer to value
        public uint Scope;          // scope of the symbol
        public uint Tag;            // pdb classification
        public uint NameLen;        // Actual length of name
        public uint MaxNameLen;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1024)]
        public string Name;

        public static SYMBOL_INFO Create()
        {
            var symbol = new SYMBOL_INFO
            {
                MaxNameLen = 1024
            };
            symbol.SizeOfStruct = (uint)Marshal.SizeOf(symbol) - 1024;   // char buffer is not counted, the ANSI version of SymFromAddr is called so each character is 1 byte long
            return symbol;
        }
    }

    //[StructLayout(LayoutKind.Sequential)]
    //public struct IMAGEHLP_LINE64
    //{
    //    public uint SizeOfStruct;           // set to sizeof(IMAGEHLP_LINE64)
    //    public ulong Key;                    // internal
    //    public uint LineNumber;             // line number in file
    //    public string FileName;               // full filename
    //    public ulong Address;                // first instruction of line
    //}

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGEHLP_LINE64
    {
        public uint SizeOfStruct;           // set to sizeof(IMAGEHLP_LINE64)
        public IntPtr Key;                    // internal
        public uint LineNumber;             // line number in file
        public IntPtr FileNameNativePtr;       // Ptr to full filename
        public ulong Address;                // first instruction of line

        /// <summary>
        /// A Get property, for comfort usage
        /// </summary>
        public string FileName
        {
            get
            {
                if (FileNameNativePtr == IntPtr.Zero)
                    return string.Empty;

                StringBuilder fn = new StringBuilder(4096); // We surely don't expect a file path greater than 4096 charecters :|
                for (int i = 0; ; ++i)
                {
                    byte b = Marshal.ReadByte(IntPtr.Add(FileNameNativePtr, i));
                    if (0 == b)
                        break;
                    fn.Append((char)b);
                }
                return fn.ToString();
            }
        }
    };

    internal static class NativeDbgHelp
    {
        // from C:\Program Files (x86)\Windows Kits\10\Debuggers\inc\dbghelp.h
        public const uint SYMOPT_UNDNAME = 0x00000002;
        public const uint SYMOPT_DEFERRED_LOADS = 0x00000004;

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymInitialize(IntPtr hProcess, string UserSearchPath, [MarshalAs(UnmanagedType.Bool)] bool fInvadeProcess);

        [DllImport("dbghelp.dll", SetLastError = true)]
        public static extern uint SymSetOptions(uint symOptions);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern ulong SymLoadModule64(IntPtr hProcess, IntPtr hFile, string imageName, string moduleName, ulong baseOfDll, uint sizeOfDll);

        // use ANSI version to ensure the right size of the structure 
        // read https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-symbol_info
        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern bool SymFromAddr(IntPtr hProcess, ulong address, out ulong displacement, ref SYMBOL_INFO symbol);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern bool SymGetSymFromAddr(IntPtr hProcess, uint address, out uint displacement, ref SYMBOL_INFO symbol);

        [DllImport("dbghelp.dll", SetLastError = true)]
        public static extern bool SymCleanup(IntPtr hProcess);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymGetLineFromAddr(IntPtr hProcess, ulong address, out uint displacement, ref IMAGEHLP_LINE64 line);
    }
}
