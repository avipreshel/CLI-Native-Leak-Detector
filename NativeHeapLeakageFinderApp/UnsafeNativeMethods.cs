using System;
using System.Runtime.InteropServices;

namespace NativeHeapLeakageFinder
{
    internal static class UnsafeNativeMethods
    {
        public static readonly uint PROCESS_ALL_ACCESS = 2097151;

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
    }
}
