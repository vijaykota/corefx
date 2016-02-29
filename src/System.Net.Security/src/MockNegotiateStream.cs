using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using System.Security.Principal;
using MockCredential = System.Net.NetworkCredential;
using MockProtection = System.Net.Security.ProtectionLevel;
using MockImpersonation = System.Security.Principal.TokenImpersonationLevel;

#if false
namespace System.Net
{
    internal class NegotiationInfoClass
    {
        internal const string NTLM = "NTLM";
        internal const string Kerberos = "Kerberos";
        internal const string Negotiate = "Negotiate";
        internal string AuthenticationPackage;
        internal NegotiationInfoClass(SafeHandle safeHandle, int negotiationState)
        {
        }
    }
}

namespace System.Net.Security
{
    public enum EncryptionPolicy
    {
        // Prohibit null ciphers (current system defaults)
        RequireEncryption = 0,

        // Add null ciphers to current system defaults
        AllowNoEncryption,

        // Request null ciphers only
        NoEncryption
    }
}
#endif

namespace System.Net.Security
{
    using MockUtils;
    using System.Net.Security;

    using OM_uint32 = System.UInt32;
    //using GssFlags = Interop.libgssapi.GssFlags;
    using NtlmFlags = Interop.NetSecurityNative.NtlmFlags;

#if false
    internal class MockCredential
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Domain { get; set; }
    }

    internal enum MockProtection
    {
        None,
        Sign,
        EncryptAndSign
    }

    internal enum MockImpersonation
    {
        Anonymous,
        Delegation,
        Identification,
        Impersonation,
        None
    }
#endif

    internal class MockGenericIdentity
    {
        private readonly string _name;
        public string Name { get { return _name;  } }
        public string AuthenticationType { get { return string.Empty; } }
        public bool IsAuthenticated { get { return true; } }

        internal MockGenericIdentity(string name)
        {
            _name = name;
        }
    }

    //internal class NegotiateStream
    public class NegotiateStream
    {
        // Does framing per MS-NNS protocol
        private readonly MockFramer _framer;

        private readonly Stream _stream;
        private SafeHandle _context;
        private bool _isSecure;
        private MockGenericIdentity _identity;
        private bool _isEncrypted;

        internal MockGenericIdentity RemoteIdentity
        {
            get
            {
                if (_identity == null)
                {
#if false
                    SecurityStatusPal errorCode;
                    var name = (string) NegotiateStreamPal.QueryContextAttributes((SafeDeleteGssContext)_context, 0x01, out errorCode);
#else
                    var name = "NOT_IMPLEMENTED";
#endif
                    _identity = new MockGenericIdentity(name);
                }
                    return _identity;
            }
        }

        internal NegotiateStream(Stream innerStream)
        {
            _stream = innerStream;
            _framer = new MockFramer(_stream);
        }

        public virtual Task AuthenticateAsServerAsync()
        {
            throw new PlatformNotSupportedException("Server side not supported");
        }

        public virtual Task AuthenticateAsClientAsync(NetworkCredential credential, string targetName)
        {
            //return Task.Factory.Run(() => AuthenticateAsClient(cred, null, targetName));
            return Task.Factory.StartNew(() => AuthenticateAsClient(credential, null, targetName));
        }

        internal void AuthenticateAsClient(MockCredential cred, object channelBinding, string target, MockProtection protection=MockProtection.EncryptAndSign, MockImpersonation impersonation=MockImpersonation.Identification)
        {
            _isSecure = (protection != MockProtection.None);
            _isEncrypted = (protection == MockProtection.EncryptAndSign);
            SafeHandle inCred;
            var isNtlm = true; // string.IsNullOrEmpty(target) || (protection == MockProtection.None);
            var package = isNtlm ? "NTLM" : "Negotiate";
            NegotiateStreamPal.AcquireCredentialsHandle(package, false, cred.UserName, cred.Password, cred.Domain, out inCred);
            //NegotiateStreamPal.AcquireDefaultCredential(string.Empty, false, out inCred);
            byte[] inBuf = null;
            while(true)
            {
                SecurityBuffer[] inputBuffers = new SecurityBuffer[] {new SecurityBuffer(inBuf, SecurityBufferType.Token)};
                SecurityBuffer outputBuffer = new SecurityBuffer(0, SecurityBufferType.Token);
                uint inFlags,outFlags=0;
#if false
                if(isNtlm) inFlags = GetNtlmFlags(false, protection, impersonation);
                else
                inFlags = GetFlags(false, protection, impersonation);
#else
                inFlags = (uint)GetNtlmFlags(false, protection, impersonation);
#endif
                var done = NegotiateStreamPal.InitializeSecurityContext(inCred, ref _context, target, inFlags, 0, inputBuffers, outputBuffer, ref outFlags);
                MockLogging.PrintInfo(null, "____________ DONE: " + done);
                if (!isNtlm && done == SecurityStatusPal.OK)
                {
                    _framer.MessageId = 20;
                    break;
                }
                _framer.WriteMessage(outputBuffer.token);
                inBuf = _framer.ReadMessage();
                if ((null == inBuf) || (inBuf.Length == 0)) break;
            }
            _identity = new MockGenericIdentity(target);
        }

        internal void AuthenticateAsServer(MockCredential cred, object extendedProtectionPolicy=null, MockProtection protection=MockProtection.EncryptAndSign, MockImpersonation impersonation=MockImpersonation.Identification)
        {
            _isSecure = (protection != MockProtection.None);
            _isEncrypted = (protection == MockProtection.EncryptAndSign);
            SafeHandle inCred;
            NegotiateStreamPal.AcquireCredentialsHandle(string.Empty, true, string.Empty, string.Empty, string.Empty, out inCred);
            byte[] inBuf = null;
            while(true)
            {
                inBuf = _framer.ReadMessage();
                SecurityBuffer inputBuffer = new SecurityBuffer(inBuf, SecurityBufferType.Token);
                SecurityBuffer outputBuffer = new SecurityBuffer(0, SecurityBufferType.Token);
                uint outFlags=0;
                //var inFlags = GetFlags(false, protection, impersonation);
                uint inFlags = 0;
                var done = NegotiateStreamPal.AcceptSecurityContext(inCred, ref _context, inputBuffer, inFlags, 0, outputBuffer, ref outFlags);
                MockLogging.PrintInfo(null, "____________ DONE: " + done);
                _framer.WriteMessage(outputBuffer.token);
                if (done==SecurityStatusPal.OK) break;
            }
        }

        internal int Read(byte[] buffer, int offset, int count)
        {
            if (!_isSecure) return _framer.ReadData(buffer, offset, count);
            var internalBuffer = new byte[count];
            count = _framer.ReadData(internalBuffer, 0, count);
            int newOffset;
            if (_isEncrypted) count = NegotiateStreamPal.Decrypt(_context, internalBuffer, 0, count, out newOffset, 0);
            else count = NegotiateStreamPal.VerifySignature(_context, internalBuffer, 0, count, out newOffset, 0);
            Array.Copy(internalBuffer, newOffset, buffer, offset, count);
            return count;
        }

        internal void Write(byte[] buffer, int offset, int count)
        {
            if (!_isSecure)
            {
                _framer.WriteData(buffer, offset, count);
                return; 
            }
            byte[] outBuf = null;
            if (_isEncrypted) count = NegotiateStreamPal.Encrypt(_context, buffer, offset, count, ref outBuf, 0);
            else count = NegotiateStreamPal.MakeSignature(_context, buffer, offset, count, ref outBuf, 0);
            _framer.WriteData(outBuf, 0, count);
        }

#region private
#if false
        private OM_uint32 GetFlags(bool isServer, MockProtection protection, MockImpersonation impersonation)
        {
            GssFlags inFlags=0;
            if (protection == MockProtection.EncryptAndSign) inFlags = GssFlags.GSS_C_CONF_FLAG;
            else if (protection == MockProtection.Sign) inFlags = GssFlags.GSS_C_REPLAY_FLAG | GssFlags.GSS_C_SEQUENCE_FLAG;
            if (!isServer)
            {
                if (protection != MockProtection.None) inFlags |= GssFlags.GSS_C_MUTUAL_FLAG;
                if (impersonation == MockImpersonation.Identification) inFlags |= GssFlags.GSS_C_IDENTIFY_FLAG;
            }
            return (OM_uint32)inFlags;
        }

        private uint GetNtlmFlags(bool isServer, MockProtection protection, MockImpersonation impersonation)
        {
            uint inFlags = NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE | NtlmFlags.NTLMSSP_REQUEST_TARGET;
#else
        private NtlmFlags GetNtlmFlags(bool isServer, MockProtection protection, MockImpersonation impersonation)
        {
            var inFlags = NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE | NtlmFlags.NTLMSSP_REQUEST_TARGET;
            if (protection != MockProtection.None) inFlags |= NtlmFlags.NTLMSSP_NEGOTIATE_SIGN | NtlmFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NtlmFlags.NTLMSSP_NEGOTIATE_NTLM | NtlmFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NtlmFlags.NTLMSSP_NEGOTIATE_128 | NtlmFlags.NTLMSSP_NEGOTIATE_KEY_EXCH;
            if (protection == MockProtection.EncryptAndSign) inFlags |= NtlmFlags.NTLMSSP_NEGOTIATE_SEAL;
            return inFlags;
        }
#endif

        private class MockFramer
        {
            private readonly Stream _stream;
            internal byte MessageId = 22; // handshake-in-progress
            internal MockFramer(Stream innerStream)
            {
                _stream = innerStream;
            }
            internal void WriteMessage(byte[] message)
            {
                // Do MS-NNS framing
                var header = new byte[5];
                header[0] = MessageId;
                header[1] = (byte) 1; // major version
                header[2] = (byte) 0; // minor version
                header[3] = (byte) ((message.Length >> 8) & 0xff);
                header[4] = (byte) (message.Length & 0xff);
                _stream.Write(header, 0, header.Length);
                
                if (message.Length > 0)
                {
                    _stream.Write(message, 0, message.Length);
                }
            }
            internal byte[] ReadMessage()
            {
                // Strip away MS-NNS framing
                var header = new byte[5];
                _stream.Read(header, 0, 1);
                _stream.Read(header, 1, 4);
                var length = (header[3] << 8) + header[4];
                var retVal = new byte[length]; // return non-null even for 0
                if (length > 0)
                {
                    _stream.Read(retVal, 0, retVal.Length);
                }
                if (header[0] == 21) throw new Exception("Received ERROR record");
                return retVal;
            }
            internal void WriteData(byte[] message, int offset, int count)
            {
                // Do MS-NNS framing
                var header = new byte[4];
                header[0] = (byte)(count & 0xff);
                header[1] = (byte)((count >> 8) & 0xff);
                header[2] = (byte)((count >> 16) & 0xff);
                header[3] = (byte)((count >> 24) & 0xff);
                _stream.Write(header, 0, header.Length);

                if (count > 0)
                {
                    _stream.Write(message, offset, count);
                }
            }
            internal int ReadData(byte[] buffer, int offset, int count)
            {
                // Strip away MS-NNS framing
                var header = new byte[4];
                _stream.Read(header, 0, 4);
                var length = (header[3] << 24) + (header[2] << 16) + (header[1] << 8) + header[0];
                if (length > 0)
                {
                    _stream.Read(buffer, offset, Math.Min(count, length));
                }
                return length;
            }
        }
#endregion
    }
}
