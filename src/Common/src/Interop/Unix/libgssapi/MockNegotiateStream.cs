using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


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

namespace MockNegotiateStream
{
    using MockUtils;
    using System.Net.Security;

    using OM_uint32 = System.UInt32;
    using ContextFlags = Interop.libgssapi.ContextFlags;
    using NtlmFlags = Interop.libheimntlm.NtlmFlags;

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

    internal class MockNegotiateStream
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
                    SecurityStatus errorCode;
                    var name = (string) NegotiateStreamPal.QueryContextAttributes((SafeDeleteGssContext)_context, 0x01, out errorCode);
                    _identity = new MockGenericIdentity(name);
                }
                return _identity;
            }
        }

        internal MockNegotiateStream(Stream innerStream)
        {
            _stream = innerStream;
            _framer = new MockFramer(_stream);
        }

        internal void AuthenticateAsClient(MockCredential cred, object channelBinding, string target, MockProtection protection=MockProtection.EncryptAndSign, MockImpersonation impersonation=MockImpersonation.Identification)
        {
            _isSecure = (protection != MockProtection.None);
            _isEncrypted = (protection == MockProtection.EncryptAndSign);
            SafeHandle inCred;
            var isNtlm = string.IsNullOrEmpty(target) || (protection == MockProtection.None);
            var package = isNtlm ? "NTLM" : "Negotiate";
            NegotiateStreamPal.AcquireCredentialsHandle(package, false, cred.UserName, cred.Password, cred.Domain, out inCred);
            //NegotiateStreamPal.AcquireDefaultCredential(string.Empty, false, out inCred);
            byte[] inBuf = null;
            while(true)
            {
                SecurityBuffer[] inputBuffers = new SecurityBuffer[] {new SecurityBuffer(inBuf, SecurityBufferType.Token)};
                SecurityBuffer outputBuffer = new SecurityBuffer(0, SecurityBufferType.Token);
                uint outFlags=0;
                var inFlags = isNtlm ? GetNtlmFlags(false, protection, impersonation) : GetFlags(false, protection, impersonation);
                var done = NegotiateStreamPal.InitializeSecurityContext(inCred, ref _context, target, inFlags, 0, inputBuffers, outputBuffer, ref outFlags);
                MockLogging.PrintInfo(null, "____________ DONE: " + done);
                // TODO: Figure out correct framing logic
                if (!isNtlm && done==SecurityStatus.OK) break;
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
                var inFlags = GetFlags(false, protection, impersonation);
                var done = NegotiateStreamPal.AcceptSecurityContext(inCred, ref _context, inputBuffer, inFlags, 0, outputBuffer, ref outFlags);
                MockLogging.PrintInfo(null, "____________ DONE: " + done);
                _framer.WriteMessage(outputBuffer.token);
                if (done==SecurityStatus.OK) break;
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
        private OM_uint32 GetFlags(bool isServer, MockProtection protection, MockImpersonation impersonation)
        {
            ContextFlags inFlags=0;
            if (protection == MockProtection.EncryptAndSign) inFlags = ContextFlags.GSS_C_CONF_FLAG;
            else if (protection == MockProtection.Sign) inFlags = ContextFlags.GSS_C_REPLAY_FLAG | ContextFlags.GSS_C_SEQUENCE_FLAG;
            if (!isServer)
            {
                if (protection != MockProtection.None) inFlags |= ContextFlags.GSS_C_MUTUAL_FLAG;
                if (impersonation == MockImpersonation.Identification) inFlags |= ContextFlags.GSS_C_IDENTIFY_FLAG;
            }
            return (OM_uint32)inFlags;
        }

        private uint GetNtlmFlags(bool isServer, MockProtection protection, MockImpersonation impersonation)
        {
            uint inFlags = NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE | NtlmFlags.NTLMSSP_REQUEST_TARGET;
            if (protection != MockProtection.None) inFlags |= NtlmFlags.NTLMSSP_NEGOTIATE_SIGN | NtlmFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NtlmFlags.NTLMSSP_NEGOTIATE_NTLM | NtlmFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NtlmFlags.NTLMSSP_NEGOTIATE_128 | NtlmFlags.NTLMSSP_NEGOTIATE_KEY_EXCH;
            if (protection == MockProtection.EncryptAndSign) inFlags |= NtlmFlags.NTLMSSP_NEGOTIATE_SEAL;
            return inFlags;
        }

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
