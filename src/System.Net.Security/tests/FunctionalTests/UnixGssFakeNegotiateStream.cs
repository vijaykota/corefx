using System;
using System.IO;
using System.Security.Authentication;
using System.Threading.Tasks;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;

namespace System.Net.Security.Tests
{
    internal partial class UnixGssFakeNegotiateStream : NegotiateStream
    {
        private static Action<object> s_serverLoop = ServerLoop;
        private static Action<object> s_msgLoop = MessageLoop;
        private readonly UnixGssFakeStreamFramer _framer;
        private SafeGssContextHandle _context;
        private volatile int _dataMsgCount;
        private bool _isNtlm;

        public UnixGssFakeNegotiateStream(Stream innerStream) : base(innerStream)
        {
            _framer = new UnixGssFakeStreamFramer(innerStream);
            _dataMsgCount = 0;
        }

        public override Task AuthenticateAsServerAsync()
        {
            return Task.Factory.StartNew(s_serverLoop, (object)this);
        }

        public Task PollMessageAsync(int count)
        {
            _dataMsgCount = count;
            return Task.Factory.StartNew(s_msgLoop, (object)this);
        }

        public static void GetDefaultKerberosCredentials(string username, string password)
        {
            // Fetch a Kerberos TGT which gets saved in the default cache
            using (SafeGssCredHandle cred = SafeGssCredHandle.Create(username, password, string.Empty))
            {
                return;
            }
        }

        private static void ServerLoop(object state)
        {
            UnixGssFakeNegotiateStream thisRef = (UnixGssFakeNegotiateStream)state;
            var header = new byte[5];
            bool handshakeDone = false;
            do
            {
                byte[] inBuf = thisRef._framer.ReadHandshakeFrame();
                byte[] outBuf = null;
                try
                {
                    handshakeDone = EstablishSecurityContext(ref thisRef._context, ref thisRef._isNtlm, inBuf, out outBuf);
                    thisRef._framer.WriteHandshakeFrame(outBuf, 0, outBuf.Length);
                }
                catch (Interop.NetSecurityNative.GssApiException e)
                {
                    thisRef._framer.WriteHandshakeFrame(e);
                    handshakeDone = true;
                }
            }
            while (!handshakeDone);
        }

        private static void MessageLoop(object state)
        {
            UnixGssFakeNegotiateStream thisRef = (UnixGssFakeNegotiateStream)state;
            var header = new byte[5];
            while (thisRef._dataMsgCount > 0)
            {
                byte[] inBuf = thisRef._framer.ReadDataFrame();
                byte[] unwrapped = UnwrapMessage(thisRef._context, inBuf);
                byte[] outMsg = WrapMessage(thisRef._context, unwrapped);
                thisRef._framer.WriteDataFrame(outMsg, 0, outMsg.Length);
                thisRef._dataMsgCount--;
            }
        }
    }
}


