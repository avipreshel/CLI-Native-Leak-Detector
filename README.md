# Native (C++) Memory Leak Detection tool
A useful tool, written in C#, for tracking native (C++) memory leakage in Windows 10 environment. The app support x86 and x64 in both Debug and Release modes.

# How to use
- Download the project and compile the solution with VS2019
- Preperations: The tracked app (the app you wish to put under inspection) should have it's PDBs in the same folder as it's .exe and .dlls, otherwise the call-stack will be empty strings, which isn't ideal.
- How to run from command line: 
  - Use process name: "NativeHeapLeakageFinder.exe SuspectedApp.exe -top:10 -hidesystemstack -ignoresingleallocs
  - top:10 will show only the top 10 results. Results are sorted according to the total amount of unallocated memory, which is the number of instances X bytes per instance
  - hidesystemstack will not show any "system" symbols in the call stack. This is to make the report more neat, as we usually don't care about system call stack
  - ignoresingleallocs this will ignore any single allocations, such as singeltons or other one-time caching which is done in the app lifecycle
- When you are done, press any key in order to generate the report output
- Press any key again to exit
 
 ![Alt text](/Screenshot.jpg?raw=true "Report example")
 
# How does it work, under the hood
This app is using ETW (Event Tracing for Windows, https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal) for listening to native (C++) memory allocation and de-allocation events coming from A given windows process.
The main idea is to find *suspected call stacks*. A suspect call stack is A call stack which got at least one outstanding heap allocation.
For example, if call stack A->B->C has allocated heap addresses 0x1 and 0x2, and address 0x2 was later freed, then A->B->C got 1 outstanding heap allocation (address 0x1).

So - 

Each time A heap allocation event arrives, the app assign it to A call stack. Call stacks are uniquely identified by their address list. 
Exaplained: ETW sends the call stack as a list of memory addresses, so, A call stack with call depth = 3 in an x64 process looks something like this:

```sh
[0x12e1161210121212, 0x1a12b2121f121212, 0xa21b1212ff121212]. 
```
In order to uniquly identify A call stack, I had to map this list of memory addresses to A key. The nai've solution would be to convert it to A long string list, but call stacks can get very long, so it was not very efficent to create A string based on that.
So, I decided to use SHA256 to generate A unique key. The reason behind using SHA256 is:
1) It creates a highly unique key, with practically zero collusion with other key
2) It's got a fixed length

I've used Base64 to convert the SHA256 key to A "readable" string key. The base64 is actually redundant, but it was easier to debug, since SHA256 creates A non-alphanumerical string. Perhaps future releases can get rid of that, and make this app runs A tad faster.

# Tech stack used
- C# w/ .Net 4.8
- Microsoft.Diagnostics.Tracing NuGet v4.3.0 (https://www.nuget.org/packages/System.Diagnostics.Tracing/4.3.0)
- P/Invoke to DbgHelp.dll v10.0.18362.1139 . A local copy of this assembly is included in this project. This assembly is part of Windows 10, yet the most up-to-date version cam be obtained from the Windows 10 SDK: https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk/. I have not tested this app with another version.
- P/Invoke to kernel32.dll
- MS Unit Test framework

# Design decisions
- As simple as possible. I originally aimed for a "one file app", but it got too messy. 
- Testable. The main object (the tracker) has a fairly simple API which is easily testable using MS Test framework.

# ToDos
- Basic UI (to select process, start / stop session, view suspected call stacks)
- Add unit test for the ETW tracker class
