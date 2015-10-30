using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace MockUtils
{
    using socklen_t = System.UInt32;
#if CODE_ANALYSIS
    using size_t = System.Int32;
#else
    using size_t = System.IntPtr;
#endif

    internal static class Interop
    {
#if CODE_ANALYSIS
        private const string mylib = "WS2_32";

        [DllImport(mylib, SetLastError = true)]
        internal static extern int WSAStartup(short version, IntPtr data);

        [DllImport(mylib, SetLastError = true)]
        internal static extern int WSASocket(int domain, int type, int protocol, IntPtr zero, int zero2, int zero3);
#else
        private const string mylib = "libc";

        [DllImport(mylib, SetLastError = true)]
        internal unsafe static extern int write(int fd, byte* buf, ulong len);

        [DllImport(mylib, SetLastError = true)]
        internal static extern int socket(int domain, int type, int protocol);
#endif

        [DllImport(mylib, SetLastError = true)]
        internal unsafe static extern int send(int sockfd, byte* buf, size_t len, int flags);

        [DllImport(mylib, SetLastError = true)]
        internal unsafe static extern int recv(int sockfd, byte* buf, size_t len, int flags);

        [DllImport(mylib, SetLastError = true)]
        internal unsafe static extern int connect(int sockfd, byte* addr, socklen_t addrlen);

        [DllImport(mylib, SetLastError = true)]
        internal unsafe static extern int bind(int sockfd, byte* addr, socklen_t addrlen);

        [DllImport(mylib, SetLastError = true)]
        internal unsafe static extern int setsockopt(int sockfd, int level, int optname, ref int optval, socklen_t optlen);

        [DllImport(mylib, SetLastError = true)]
        internal unsafe static extern int listen(int sockfd, int backlog);

        [DllImport(mylib, SetLastError = true)]
        internal unsafe static extern int accept(int sockfd, byte* addr, IntPtr addrlen);
    }

    internal static class MockLogging
    {
        private static void Print(string msg)
        {
            string logHeader = "[" + Environment.CurrentManagedThreadId.ToString("d4") + "] ";
#if CODE_ANALYSIS
            Console.Write(logHeader + msg);
#else
            var byteBuf = Encoding.UTF8.GetBytes(logHeader + msg);
            unsafe
            {
                fixed (byte* bytePtr = byteBuf)
                {
                    Interop.write(1, bytePtr, (ulong)byteBuf.Length);
                }
            }
#endif
        }

        internal static void PrintInfo(object t, string message)
        {
            Print(message + "\n");
        }

        internal static void Dump(object t, object t2, string method, byte[] buf, int offset, int len)
        {
            unsafe
            {
                fixed (byte* ptr = buf)
                {
                    Dump(t, t2, method, new IntPtr(ptr + offset), len);
                }
            }
        }

        internal static void Dump(object t, object t2, string method, IntPtr buf, int len)
        {
            Print("DUMPING from " + method + ": " + len + " bytes" + "\n");
            if (len > 256) len = 256;
            for (int i = 0; i < len;)
            {
                var s1 = new StringBuilder(16*3);
                var s2 = new StringBuilder(16);

                var s0 = "\t" + (i & (~0xf)).ToString("x8") + "\t";
                for (int j = 0; j < 16; j++, i++)
                {
                    if (i < len)
                    {
                        var b = Marshal.ReadByte(buf, i);
                        s1.Append(b.ToString("X2") + " ");
                        var c = (b > 31 && b < 128) ? Convert.ToChar(b) : '.';
                        s2.Append(c);
                    }
                    else
                    {
                        s1.Append("   ");
                    }
                }
                Print(s0 + s1.ToString() + "\t" + s2.ToString() + "\n");
            }
        }

        internal static void PrintLine(object t, TraceEventType t2, int t3, string message)
        {
            PrintInfo(null, message);
        }

        internal static void PrintError(object t, string message)
        {
            PrintInfo(null, message);
        }
    }

    internal class SocketStream : MemoryStream
    {
        protected int _socket;
        protected static readonly byte[] s_connBuffer = new byte[] { 2, 0, 0x11, 0x51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

#if CODE_ANALYSIS
        static SocketStream()
        {
            var ret = Interop.WSAStartup((short)0x202, Marshal.AllocHGlobal(1000));
            if (ret != 0) throw new Exception("WSAStartup failed: " + ret);
        }
#endif

        public SocketStream(int socket)
        {
            _socket = socket;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var retVal = SendRecvHelper(_socket, buffer, offset, count, false);
            return retVal;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            var retVal = SendRecvHelper(_socket, buffer, offset, count, true);
        }
        protected static int GetPort(int port)
        {
            if (port == 0) port = (s_connBuffer[2] << 8) + s_connBuffer[3];
            return port;
        }

        protected static int GetSocket()
        {
#if CODE_ANALYSIS
            var socket = Interop.WSASocket(2, 1, 0, IntPtr.Zero, 0, 0);
#else
            var socket = Interop.socket(2, 1, 0);
#endif
            return socket;
        }

        private static int SendRecvHelper(int sockFd, byte[] buffer, int offset, int count, bool isSend)
        {
            var method = isSend ? "SendHelper" : "RecvHelper";
            unsafe
            {
                fixed (byte* bytePtr = buffer)
                {
#if CODE_ANALYSIS
                    size_t bufSize = (size_t)count;
#else
                    size_t bufSize = new IntPtr(count);
#endif
                    if (isSend)
                    {
                        count = Interop.send(sockFd, bytePtr + offset, bufSize, 0);
                    }
                    else
                    {
                        count = Interop.recv(sockFd, bytePtr + offset, bufSize, 0);
                    }

                    MockLogging.PrintLine(null, TraceEventType.Verbose, 0, method + ": " + count);
                    if (count < 0)
                    {
                        MockLogging.PrintError(null, method + " failed: " + count + " errno: " + Marshal.GetLastWin32Error());
                        throw new Exception(method);
                    }
                    if (isSend) MockLogging.PrintLine(null, TraceEventType.Verbose, 0, method + " sent: " + count);
                    else
                    {
                        MockLogging.Dump(null, null, method, buffer, offset, count);
                    }
                    return count;
                }
            }
        }
    }

    internal class ClientStream : SocketStream
    {
        public ClientStream(string server, int port)
            : base(-1)
        {
            if (String.IsNullOrEmpty(server)) server = "127.0.0.1";
            _socket = CreateServerConnection(IPAddress.Parse(server), GetPort(port));
        }

        private static int CreateServerConnection(IPAddress server, int port)
        {
            var client = GetSocket();
            var size = s_connBuffer.Length;
            var buffer = new byte[size];
            Array.Copy(s_connBuffer, buffer, size);
            var addrBytes = server.GetAddressBytes();
            Array.Copy(addrBytes, 0, buffer, 4, 4);

            unsafe
            {
                fixed (byte* pinnedBuffer = buffer)
                {
                    var retVal = Interop.connect(client, pinnedBuffer, (socklen_t)size);
                    if (retVal < 0) throw new Exception("connect returned: " + retVal);
                    return client;
                }
            }
        }
    }

    internal class ServerStream : SocketStream
    {
        internal ServerStream(int port)
            : base(-1)
        {
            _socket = AcceptClientConnection(GetPort(port));
        }

        private int AcceptClientConnection(int port)
        {
            var listenSocket = GetSocket();
            var size = s_connBuffer.Length;
            var buffer = s_connBuffer;
            unsafe
            {
                fixed (byte* pinnedBuffer = buffer)
                {
                    var retVal = Interop.bind(listenSocket, pinnedBuffer, (socklen_t)size);
#if false
                    if (retVal < 0) throw new Exception("bind returned: " + retVal);
                    int on=1;
                    retVal = Interop.setsockopt(listenSocket, 1, 2, ref on, (socklen_t)4);
                    if (retVal < 0) throw new Exception("setsockopt returned: " + retVal);
#else
                    int retry = 20,delay=500,i=1; // 10 seconds == 20 * 500
                    while (retVal < 0 && i <= retry)
                    {
                        retVal = Interop.bind(listenSocket, pinnedBuffer, (socklen_t)size);
                        if (retVal >= 0) break;
                        else if (i == retry) throw new Exception("bind returned: " + retVal);
                        i++;
                        System.Threading.Tasks.Task.Delay(delay).Wait();
                    }
#endif
                    retVal = Interop.listen(listenSocket, 1);
                    if (retVal < 0) throw new Exception("listen returned: " + retVal);
                    MockLogging.PrintInfo(null, "listen returned: " + retVal + ". Waiting for client connection...");
                    var paddr = Marshal.AllocHGlobal(sizeof(socklen_t));
                    Marshal.WriteInt32(paddr, 0, size);
                    var acceptSocket = Interop.accept(listenSocket, pinnedBuffer, paddr);
                    MockLogging.PrintInfo(null, "AcceptClientConnection returned: " + acceptSocket);
                    return acceptSocket;
                }
            }
        }
    }
}
