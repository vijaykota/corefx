using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace System.Net.Security.Tests
{
    // TODO: Move to separate class
    internal class UnixGssFakeStreamFramer
    {
        private readonly Stream _innerStream;
        private readonly byte[] _header = new byte[5];

        public UnixGssFakeStreamFramer(Stream innerStream)
        {
            _innerStream = innerStream;
        }

        public void WriteFrame(byte[] buffer, int offset, int count)
        {
            _header[0] = 20; // TODO: Define consts for these 3 fields
            _header[1] = (byte)1; // major version
            _header[2] = (byte)0; // minor version
            _header[3] = (byte)((count >> 8) & 0xff);
            _header[4] = (byte)(count & 0xff);
            _innerStream.Write(_header, 0, _header.Length);
            if (count > 0)
            {
                _innerStream.Write(buffer, offset, count);
            }
        }

        public byte[] ReadFrame()
        {
            _innerStream.Read(_header, 0, _header.Length);
            byte[] inBuf = new byte[(_header[3] << 8) + _header[4]];
            _innerStream.Read(inBuf, 0, inBuf.Length);
            return inBuf;
        }
    }

    internal class UnixGssFakeNegotiateStream : NegotiateStream
    {
        private static Action<object> s_serverLoop = ServerLoop;
        private readonly UnixGssFakeStreamFramer _framer;
        private SafeGssContextHandle _context;

        public static bool CheckAndInitializeKerberos()
        {
            // TODO: Check for KDC setup. File.Exists(/etc/krb5.conf) works on all platforms
            // TODO: Clear Kerberos cache if KDC is setup. Process.Run("kdestroy -A")
            return true;
        }

        public UnixGssFakeNegotiateStream(Stream innerStream) : base(innerStream)
        {
            _framer = new UnixGssFakeStreamFramer(innerStream);
        }

        public override Task AuthenticateAsClientAsync(NetworkCredential credential, string targetName)
        {
            return base.AuthenticateAsClientAsync(credential, targetName);
        }

        public override Task AuthenticateAsServerAsync()
        {
            return Task.Factory.StartNew(s_serverLoop, (object)this);
        }

        private static void ServerLoop(object state)
        {
            UnixGssFakeNegotiateStream thisRef = (UnixGssFakeNegotiateStream)state;
            var header = new byte[5];
            bool done = false;
            do
            {
                byte[] inBuf = thisRef._framer.ReadFrame();
                byte[] outBuf = null;
                done = EstablishSecurityContext(ref thisRef._context, inBuf, out outBuf);
                thisRef._framer.WriteFrame(outBuf, 0, outBuf.Length);
            }
            while (!done);
        }

        private static bool EstablishSecurityContext(
            ref SafeGssContextHandle context,
            byte[] buffer,
            out byte[] outputBuffer)
        {
            outputBuffer = null;

            // EstablishSecurityContext is called multiple times in a session.
            // In each call, we need to pass the context handle from the previous call.
            // For the first call, the context handle will be null.
            if (context == null)
            {
                context = new SafeGssContextHandle();
            }

            Interop.NetSecurityNative.GssBuffer token = default(Interop.NetSecurityNative.GssBuffer);
            Interop.NetSecurityNative.Status status;

            try
            {
                Interop.NetSecurityNative.Status minorStatus;
                status = Interop.NetSecurityNative.AcceptSecContext(out minorStatus,
                                                          ref context,
                                                          buffer,
                                                          (buffer == null) ? 0 : buffer.Length,
                                                          ref token);

                if ((status != Interop.NetSecurityNative.Status.GSS_S_COMPLETE) && (status != Interop.NetSecurityNative.Status.GSS_S_CONTINUE_NEEDED))
                {
                    throw new Interop.NetSecurityNative.GssApiException(status, minorStatus);
                }

                outputBuffer = token.ToByteArray();
            }
            finally
            {
                token.Dispose();
            }

            return status == Interop.NetSecurityNative.Status.GSS_S_COMPLETE;
        }
    }
}
