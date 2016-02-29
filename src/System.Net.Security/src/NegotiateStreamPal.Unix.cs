// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Net.Security;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.Net.Security
{
    //internal sealed partial class SafeFreeNegoCredentials : SafeFreeCredentials
    internal sealed partial class SafeFreeNtlmCredentials : SafeHandle
    {
        //private SafeGssCredHandle _credential;
        private readonly string _username;
        private readonly string _domain;
        private bool _isNtlm;
        private bool _isDefault;

#if false
        public SafeGssCredHandle GssCredential
        {
            get { return _credential; }
        }
#endif

        public override bool IsInvalid
        {
            //get { return (null == _credential); }
            get { return true; }
        }

        public string UserName
        {
            get { return _username; }
        }

        public string Domain
        {
            get { return _domain; }
        }

        public bool IsNtlm
        {
            get { return _isNtlm; }
        }

        public bool IsDefault
        {
            get { return _isDefault; }
        }

        protected override bool ReleaseHandle()
        {
#if false
            _credential.Dispose();
            _credential = null;
#endif
            return true;
        }
        private readonly string _password;

        public string Password
        {
            get { return _password; }
        }

        //public SafeFreeNegoCredentials(bool ntlmOnly, string username, string password, string domain) : base(IntPtr.Zero, true)
        public SafeFreeNtlmCredentials(bool ntlmOnly, string username, string password, string domain) : base(IntPtr.Zero, true)
        {
            _isNtlm = ntlmOnly;
            _isDefault = string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password);
#if false
            if (!ntlmOnly)
            {
                try
                {
                    _credential = SafeGssCredHandle.Create(username, password, domain);
                }
                catch
                {
                    // NTLM fallback is not possible with default credentials
                    if (_isDefault)
                    {
                        throw new PlatformNotSupportedException();
                    }
                    _isNtlm = true;
                }
            }
#else
            _isNtlm = true;
#endif
            // Even if Kerberos TGT could be obtained, we might later need
            // to fall back to NTLM if service ticket cannot be fetched
            _username = username;
            _password = password;
            _domain = domain;
        }
    }

    //internal sealed partial class SafeDeleteNegoContext : SafeDeleteContext
    internal sealed partial class SafeDeleteNtlmContext : SafeHandle
    {
#if false
        private SafeGssNameHandle _targetName;
        private SafeGssContextHandle _context;
#endif
        private SafeFreeNtlmCredentials _credential;
#if false
        private bool _isNtlm;

        public SafeGssNameHandle TargetName
        {
            get { return _targetName; }
        }

        public SafeGssContextHandle GssContext
        {
            get { return _context; }
        }

        public bool IsNtlm
        {
            get { return _isNtlm; }
        }

        public SafeDeleteNegoContext(SafeFreeNegoCredentials credential, string targetName)
            : base(credential)
        {
            try
            {
                _targetName = SafeGssNameHandle.CreatePrincipal(targetName);
            }
            catch
            {
                base.ReleaseHandle();
                throw;
            }
        }
        public void SetGssContext(SafeGssContextHandle context, bool isNtlm)
        {
            Debug.Assert(!context.IsInvalid, "Invalid context passed to SafeDeleteNegoContext");
            _context = context;
            _isNtlm = isNtlm;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (null != _context)
                {
                    _context.Dispose();
                    _context = null;
                }
                if (null != _targetName)
                {
                    _targetName.Dispose();
                    _targetName = null;
                }
            }
            base.Dispose(disposing);
        }
#else
        public override bool IsInvalid
        {
            get { return (null == _credential); }
        }

        protected override bool ReleaseHandle()
        {
            _credential.DangerousRelease();
            _credential = null;
            return true;
        }

#endif

        private readonly Interop.NetSecurityNative.NtlmFlags _flags;
        private Interop.HeimdalNtlm.SigningKey _serverSignKey;
        private Interop.HeimdalNtlm.SealingKey _serverSealKey;
        private Interop.HeimdalNtlm.SigningKey _clientSignKey;
        private Interop.HeimdalNtlm.SealingKey _clientSealKey;

        public Interop.NetSecurityNative.NtlmFlags Flags
        {
            get { return _flags; }
        }

#if false
        public SafeDeleteNegoContext(SafeFreeNegoCredentials credential, Interop.NetSecurityNative.NtlmFlags flags)
            : base(credential)
        {
            _flags = flags;
            _isNtlm = true;
        }
#else
        public SafeDeleteNtlmContext(SafeFreeNtlmCredentials credential, Interop.NetSecurityNative.NtlmFlags flags)
            : base(IntPtr.Zero, true)
        {
            _flags = flags;
            bool ignore = false;
            _credential = credential;
            credential.DangerousAddRef(ref ignore);
        }
#endif

        public void SetKeys(byte[] sessionKey)
        {
            Interop.HeimdalNtlm.CreateKeys(sessionKey, out _serverSignKey, out _serverSealKey, out _clientSignKey, out _clientSealKey);
        }

        public byte[] MakeClientSignature(byte[] buffer, int offset, int count)
        {

            Debug.Assert(_clientSignKey != null, "_clientSignKey cannot be null");
            return _clientSignKey.Sign(_clientSealKey, buffer, offset, count);
        }

        public byte[] MakeServerSignature(byte[] buffer, int offset, int count)
        {
            Debug.Assert(_serverSignKey != null, "_serverSignKey cannot be null");
            return _serverSignKey.Sign(_serverSealKey, buffer, offset, count);
        }

        public byte[] Encrypt(byte[] buffer, int offset, int count)
        {
            Debug.Assert(_clientSignKey != null, "_clientSealKey cannot be null");
            return _clientSealKey.SealOrUnseal(buffer, offset, count);
        }

        public byte[] Decrypt(byte[] buffer, int offset, int count)
        {

            Debug.Assert(_serverSignKey != null, "_serverSealKey cannot be null");
            return _serverSealKey.SealOrUnseal(buffer, offset, count);
        }

    }

}


namespace System.Net
{
    // Depending on PAL refactoring, this will either be part of a class that implements
    // SSPIInterfaceNego or Unix-specific files (eg. _NTAuthenticationPal.Unix.cs) will 
    // call into methods of this class
    internal static class NegotiateStreamPal
    {
        public static SecurityStatusPal AcquireCredentialsHandle(
            string moduleName,
            bool isInBoundCred,
            string username,
            string password,
            string domain,
            out SafeHandle outCredential)
        {
#if true
            outCredential = new SafeFreeNtlmCredentials(true, username, password, domain);
#else
            if (isInBoundCred || string.IsNullOrEmpty(username))
            {
                // In server case, only the keytab file (eg. /etc/krb5.keytab) is used
                // In client case, equivalent of default credentials is to use previous,
                // unexpired Kerberos TGT to get service-specific ticket.
                outCredential = new SafeFreeGssCredentials(string.Empty, string.Empty, string.Empty);
            }
            else if (string.Equals(moduleName, "NTLM"))
            {
                outCredential = new SafeFreeNtlmCredentials(username, password, domain);
            }
            else
            {
                outCredential = new SafeFreeGssCredentials(username, password, domain);
                // TODO (Issue #3717): Fall back to NTLM if Kerberos ticket cannot be obtained
            }
#endif
            return SecurityStatusPal.OK;
        }

        public static SecurityStatusPal AcquireDefaultCredential(string moduleName, bool isInBoundCred, out SafeHandle outCredential)
        {
            return AcquireCredentialsHandle(moduleName, isInBoundCred, string.Empty, string.Empty, string.Empty, out outCredential);
        }

        public static SecurityStatusPal AcceptSecurityContext(
            SafeHandle credential,
            ref SafeHandle context,
            SecurityBuffer inputBuffer,
            uint inFlags,
            uint endianNess,
            SecurityBuffer outputBuffer,
            ref uint outFlags)
        {
#if false
            return EstablishSecurityContext((SafeFreeGssCredentials)credential, ref context, string.Empty, (Interop.libgssapi.GssFlags)inFlags, inputBuffer, outputBuffer, ref outFlags);
#else
            throw new PlatformNotSupportedException();
#endif
        }

        public static SecurityStatusPal InitializeSecurityContext(
            SafeHandle credential,
            ref SafeHandle context,
            string targetName,
            uint inFlags,
            uint endianNess,
            SecurityBuffer[] inputBuffers,
            SecurityBuffer outputBuffer,
            ref uint outFlags)
        {
            // TODO (Issue #3718): The second buffer can contain a channel binding which is not yet supported
            if (inputBuffers.Length > 1)
            {
                throw new NotImplementedException("No support for channel binding on non-Windows");
            }

            //if (IsNtlmClient(targetName, credential))
            {
                return InitializeNtlmSecurityContext((SafeFreeNtlmCredentials)credential, ref context, inFlags, inputBuffers[0], outputBuffer);
            }
            //return EstablishSecurityContext((SafeFreeGssCredentials)credential, ref context, targetName, (Interop.libgssapi.GssFlags)inFlags, inputBuffers[0], outputBuffer, ref outFlags);
        }

        public static int Encrypt(SafeHandle securityContext, byte[] buffer, int offset, int count, ref byte[] output, uint sequenceNumber)
        {
#if false
            if (securityContext is SafeDeleteGssContext)
            {
                // Sequence number is not used by libgssapi
                SafeDeleteGssContext gssContext = securityContext as SafeDeleteGssContext;
                return Interop.GssApi.Encrypt(gssContext.GssContext, gssContext.NeedsEncryption, buffer, offset, count, out output);
            }
#endif

            SafeDeleteNtlmContext context = securityContext as SafeDeleteNtlmContext;
#if false
            byte[] cipher = context.EncryptOrDecrypt(true, buffer, offset, count);
            byte[] signature = context.MakeSignature(true, buffer, offset, count);
#else
            byte[] cipher = context.Encrypt(buffer, offset, count);
            var signature = context.MakeClientSignature(buffer, offset, count);
#endif
            output = new byte[cipher.Length + signature.Length];
            Array.Copy(signature, 0, output, 0, signature.Length);
            Array.Copy(cipher, 0, output, signature.Length, cipher.Length);
            return output.Length;
        }

        public static int Decrypt(SafeHandle securityContext, byte[] buffer, int offset, int count, out int newOffset, uint sequenceNumber)
        {
#if false
            if (securityContext is SafeDeleteGssContext)
            {
                // Sequence number is not used by libgssapi
                newOffset = offset;
                return Interop.GssApi.Decrypt(((SafeDeleteGssContext)securityContext).GssContext, buffer, offset, count);
            }
#endif
            SafeDeleteNtlmContext context = securityContext as SafeDeleteNtlmContext;
            //byte[] message = context.EncryptOrDecrypt(false, buffer, (offset + 16), (count - 16));
            byte[] message = context.Decrypt(buffer, (offset + 16), (count - 16));
            Array.Copy(message, 0, buffer, (offset + 16), message.Length);
            return VerifySignature(securityContext, buffer, offset, count, out newOffset, sequenceNumber);
        }

        public static int MakeSignature(SafeHandle securityContext, byte[] buffer, int offset, int count, ref byte[] output, uint sequenceNumber)
        {
#if false
            if (securityContext is SafeDeleteGssContext)
            {
                // Sequence number is not used by libgssapi
                SafeDeleteGssContext context = ((SafeDeleteGssContext)securityContext);
                return Interop.GssApi.Encrypt(context.GssContext, context.NeedsEncryption, buffer, offset, count, out output);
            }
            byte[] signature = ((SafeDeleteNtlmContext) securityContext).MakeSignature(true, buffer, offset, count);
#endif
            byte[] signature = ((SafeDeleteNtlmContext) securityContext).MakeClientSignature(buffer, offset, count);
            output = new byte[signature.Length + count];
            Array.Copy(signature, 0, output, 0, signature.Length);
            Array.Copy(buffer, offset, output, signature.Length, count);
            return output.Length;
        }

        public static int VerifySignature(SafeHandle securityContext, byte[] buffer, int offset, int count, out int newOffset, uint sequenceNumber)
        {
#if false
            if (securityContext is SafeDeleteGssContext)
            {
                // Sequence number is not used by libgssapi
                newOffset = offset;
                return Interop.GssApi.Decrypt(((SafeDeleteGssContext)securityContext).GssContext, buffer, offset, count);
            }
#endif
            newOffset = offset + 16;
            count -= 16;
            byte[] signature = ((SafeDeleteNtlmContext) securityContext).MakeServerSignature(buffer, newOffset, count);
            for (int i = 0; i < signature.Length; i++)
            {
                if (buffer[offset + i] != signature[i]) throw new Exception("Invalid signature");
            }
            return count;
        }

#if false
        public static object QueryContextAttributes(SafeDeleteGssContext context, uint attribute, out SecurityStatusPal errorCode)
        {
            errorCode = SecurityStatusPal.OK;
            switch (attribute)
            {
                case 0x01: // Names
                    return Interop.GssApi.GetSourceName(context.GssContext);
                case 0x0C: // NegotiationInfo
                    NegotiationInfoClass negotiationInfoClass = new NegotiationInfoClass(context, Int32.MaxValue);
                    negotiationInfoClass.AuthenticationPackage = NegotiationInfoClass.Kerberos;
                    return negotiationInfoClass;
                case 0: // Sizes
                    // Used only in the Encrypt/Decrypt logic
                case 0x1B: // ClientSpecifiedSpn
                    // Required only in NTLM case with ExtendedProtection
                default:
                    errorCode = SecurityStatusPal.Unsupported;
                    return null;
            }
        }

        private static bool IsNtlmClient(string targetName, SafeHandle credential)
        {
            return string.IsNullOrEmpty(targetName) || (credential is SafeFreeNtlmCredentials);
        }
#endif

        private static SecurityStatusPal InitializeNtlmSecurityContext(
            SafeFreeNtlmCredentials credential,
            ref SafeHandle context,
            uint inFlags,
            SecurityBuffer inputBuffer,
            SecurityBuffer outputBuffer)
        {
#if true
            SecurityStatusPal retVal;

            if (null == context)
            {
                context = new SafeDeleteNtlmContext(credential, (Interop.NetSecurityNative.NtlmFlags)inFlags);
                outputBuffer.token = Interop.HeimdalNtlm.CreateNegotiateMessage(inFlags);
                retVal = SecurityStatusPal.ContinueNeeded;
            }
            else
            {
                //uint flags = ((SafeDeleteNtlmContext)context).Flags;
                uint flags = (uint)((SafeDeleteNtlmContext)context).Flags;
                //SafeNtlmBufferHandle sessionKey;
                byte[] sessionKey;
                outputBuffer.token = Interop.HeimdalNtlm.CreateAuthenticateMessage(flags, credential.UserName,
                    credential.Password, credential.Domain, inputBuffer.token, inputBuffer.offset, inputBuffer.size, out sessionKey);
                //using (sessionKey)
                {
                    ((SafeDeleteNtlmContext)context).SetKeys(sessionKey);
                }
                retVal = SecurityStatusPal.OK;
            }
            outputBuffer.size = outputBuffer.token.Length;
#else
            var retVal = SecurityStatusPal.Unsupported;
#endif
            return retVal;
        }

#if false
        private static SecurityStatusPal EstablishSecurityContext(
            SafeFreeGssCredentials credential,
            ref SafeHandle context,
            string targetName,
            Interop.libgssapi.GssFlags inFlags,
            SecurityBuffer inputBuffer,
            SecurityBuffer outputBuffer,
            ref uint outFlags)
        {
            if (context == null)
            {
                context = new SafeDeleteGssContext(targetName, inFlags);
            }

            SafeDeleteGssContext gssContext = (SafeDeleteGssContext) context;
            try
            {
                SafeGssContextHandle contextHandle = gssContext.GssContext;
                bool done = Interop.GssApi.EstablishSecurityContext(
                                  ref contextHandle,
                                  credential.GssCredential,
                                  gssContext.TargetName,
                                  inFlags,
                                  inputBuffer.token,
                                  out outputBuffer.token,
                                  out outFlags);

                Debug.Assert(outputBuffer.token != null, "Unexpected null buffer returned by GssApi");
                outputBuffer.size = outputBuffer.token.Length;
                outputBuffer.offset = 0;

                // Save the inner context handle for further calls to libgssapi
                if (gssContext.IsInvalid)
                {
                    gssContext.SetHandle(credential, contextHandle);
                }
                return done ? SecurityStatusPal.OK : SecurityStatusPal.ContinueNeeded;
            }
            catch (Exception)
            {
                return SecurityStatusPal.InternalError;
            }
        }
#endif
    }   
}

