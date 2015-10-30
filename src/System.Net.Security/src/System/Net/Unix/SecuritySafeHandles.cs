// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Win32.SafeHandles;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace System.Net.Security
{
#if false
#if DEBUG
    internal sealed class SafeFreeCertContext : DebugSafeHandle
    {
#else
    internal sealed class SafeFreeCertContext : SafeHandle
    {
#endif
        private readonly SafeX509Handle _certificate;

        public SafeFreeCertContext(SafeX509Handle certificate) : base(IntPtr.Zero, true)
        {
            // In certain scenarios (eg. server querying for a client cert), the
            // input certificate may be invalid and this is OK
            if ((null != certificate) && !certificate.IsInvalid)
            {
                bool gotRef = false;
                certificate.DangerousAddRef(ref gotRef);
                Debug.Assert(gotRef, "Unexpected failure in AddRef of certificate");
                _certificate = certificate;
                handle = _certificate.DangerousGetHandle();
            }
        }

        public override bool IsInvalid
        {
            get
            {
                return handle == IntPtr.Zero;
            }
        }

        protected override bool ReleaseHandle()
        {
            _certificate.DangerousRelease();
            _certificate.Dispose();
            return true;
        }
    }

    //
    // Implementation of handles dependable on FreeCredentialsHandle
    //
#if DEBUG
    internal sealed class SafeFreeCredentials : DebugSafeHandle
    {
#else
    internal sealed class SafeFreeCredentials : SafeHandle
    {
#endif
        private SafeX509Handle _certHandle;
        private SafeEvpPKeyHandle _certKeyHandle;
        private SslProtocols _protocols = SslProtocols.None;
        private EncryptionPolicy _policy;

        internal SafeX509Handle CertHandle
        {
            get { return _certHandle; }
        }

        internal SafeEvpPKeyHandle CertKeyHandle
        {
            get { return _certKeyHandle; }
        }

        internal SslProtocols Protocols
        {
            get { return _protocols; }
        }

        public SafeFreeCredentials(X509Certificate certificate, SslProtocols protocols, EncryptionPolicy policy)
            : base(IntPtr.Zero, true)
        {
            Debug.Assert(
                certificate == null || certificate is X509Certificate2,
                "Only X509Certificate2 certificates are supported at this time");

            X509Certificate2 cert = (X509Certificate2)certificate;

            if (cert != null)
            {
                Debug.Assert(cert.HasPrivateKey, "cert.HasPrivateKey");

                using (RSAOpenSsl rsa = (RSAOpenSsl)cert.GetRSAPrivateKey())
                {
                    if (rsa != null)
                    {
                        _certKeyHandle = rsa.DuplicateKeyHandle();
                        Interop.libcrypto.CheckValidOpenSslHandle(_certKeyHandle);
                    }
                }

                // TODO (3390): Add support for ECDSA.

                Debug.Assert(_certKeyHandle != null, "Failed to extract a private key handle");

                _certHandle = Interop.libcrypto.X509_dup(cert.Handle);
                Interop.libcrypto.CheckValidOpenSslHandle(_certHandle);
            }

            _protocols = protocols;
            _policy = policy;
        }

        public override bool IsInvalid
        {
            get { return SslProtocols.None == _protocols; }
        }

        protected override bool ReleaseHandle()
        {
            if (_certHandle != null)
            {
                _certHandle.Dispose();
            }

            if (_certKeyHandle != null)
            {
                _certKeyHandle.Dispose();
            }

            _protocols = SslProtocols.None;
            return true;
        }

    }

    //
    // This is a class holding a Credential handle reference, used for static handles cache
    //
#if DEBUG
    internal sealed class SafeCredentialReference : DebugCriticalHandleMinusOneIsInvalid
    {
#else
    internal sealed class SafeCredentialReference : CriticalHandleMinusOneIsInvalid
    {
#endif

        //
        // Static cache will return the target handle if found the reference in the table.
        //
        internal SafeFreeCredentials Target;

        internal static SafeCredentialReference CreateReference(SafeFreeCredentials target)
        {
            SafeCredentialReference result = new SafeCredentialReference(target);
            if (result.IsInvalid)
            {
                return null;
            }

            return result;
        }
        private SafeCredentialReference(SafeFreeCredentials target) : base()
        {
            // Bumps up the refcount on Target to signify that target handle is statically cached so
            // its dispose should be postponed
            bool ignore = false;
            target.DangerousAddRef(ref ignore);
            Target = target;
            SetHandle(new IntPtr(0));   // make this handle valid
        }

        protected override bool ReleaseHandle()
        {
            SafeFreeCredentials target = Target;
            if (target != null)
            {
                target.DangerousRelease();
            }

            Target = null;
            return true;
        }
    }

#if DEBUG
    internal sealed class SafeDeleteContext : DebugSafeHandle
    {
#else
    internal sealed class SafeDeleteContext : SafeHandle
    {
#endif
        private readonly SafeFreeCredentials _credential;
        private readonly Interop.libssl.SafeSslHandle _sslContext;

        public Interop.libssl.SafeSslHandle SslContext
        {
            get
            {
                return _sslContext;
            }
        }

        public SafeDeleteContext(SafeFreeCredentials credential, long options, bool isServer, bool remoteCertRequired)
            : base(IntPtr.Zero, true)
        {
            Debug.Assert((null != credential) && !credential.IsInvalid, "Invalid credential used in SafeDeleteContext");

            // When a credential handle is first associated with the context we keep credential
            // ref count bumped up to ensure ordered finalization. The certificate handle and
            // key handle are used in the SSL data structures and should survive the lifetime of
            // the SSL context
            bool ignore = false;
            _credential = credential;
            _credential.DangerousAddRef(ref ignore);

            try
            {
                _sslContext = Interop.OpenSsl.AllocateSslContext(
                    options,
                    credential.CertHandle,
                    credential.CertKeyHandle,
                    isServer,
                    remoteCertRequired);
            }
            finally
            {
                if (IsInvalid)
                {
                    _credential.DangerousRelease();
                }
            }
        }

        public override bool IsInvalid
        {
            get
            {
                return (null == _sslContext) || _sslContext.IsInvalid;
            }
        }

        protected override bool ReleaseHandle()
        {
            Interop.OpenSsl.FreeSslContext(_sslContext);
            Debug.Assert((null != _credential) && !_credential.IsInvalid, "Invalid credential saved in SafeDeleteContext");
            _credential.DangerousRelease();
            return true;
        }

        public override string ToString()
        {
            return IsInvalid ? String.Empty : handle.ToString();
        }
    }

    internal abstract class SafeFreeContextBufferChannelBinding : ChannelBinding
    {
        // TODO (Issue #3362) To be implemented
    }
#endif

    internal sealed class SafeFreeGssCredentials : Interop.libgssapi.SafeGssCredHandle
    {
        public SafeFreeGssCredentials(string username, string password, string domain) : base(username, password, domain)
        {
        }
    }

    internal sealed class SafeDeleteGssContext : SafeHandle
    {
        private readonly Interop.libgssapi.SafeGssNameHandle _targetName;
        private SafeFreeGssCredentials _credential;
        private Interop.libgssapi.SafeGssContextHandle _context;
        private bool _encryptAndSign;

        public Interop.libgssapi.SafeGssNameHandle TargetName
        {
            get { return _targetName; }
        }

        public Interop.libgssapi.SafeGssContextHandle GssContext
        {
            get { return _context; }
        }

        public bool NeedsEncryption
        {
            get { return _encryptAndSign; }
        }

        public SafeDeleteGssContext(string targetName, uint flags) : base(IntPtr.Zero, true)
        {
            // In server case, targetName can be null or empty
            if (!String.IsNullOrEmpty(targetName))
            {
                _targetName = new Interop.libgssapi.SafeGssNameHandle(targetName,
                    Interop.libgssapi.GSS_KRB5_NT_PRINCIPAL_NAME);
            }

            _encryptAndSign = (flags & (uint) Interop.libgssapi.ContextFlags.GSS_C_CONF_FLAG) != 0;
        }

        public override bool IsInvalid
        {
            get { return (null == _context) || _context.IsInvalid; }
        }

        public void SetHandle(SafeFreeGssCredentials credential, Interop.libgssapi.SafeGssContextHandle context)
        {
            Debug.Assert(!context.IsInvalid, "Invalid context passed to SafeDeleteGssContext");
            _context = context;

            // After context establishment is initiated, callers expect SafeDeleteGssContext
            // to bump up the ref count.
            // NOTE: When using default credentials, the credential handle may be invalid
            if ((null != credential) && !credential.IsInvalid)
            {
                bool ignore = false;
                _credential = credential;
                _credential.DangerousAddRef(ref ignore);
            }
        }

        protected override bool ReleaseHandle()
        {
            if ((null != _credential) && !_credential.IsInvalid)
            {
                _credential.DangerousRelease();
            }
            _context.Dispose();
            if (_targetName != null)
            {
                _targetName.Dispose();
            }
            return true;
        }
    }

    internal sealed class SafeFreeNtlmCredentials : SafeHandle
    {
        private readonly string _username;
        private readonly string _password;
        private readonly string _domain;

        public string UserName
        {
            get { return _username; }
        }

        public string Password
        {
            get { return _password; }
        }

        public string Domain
        {
            get { return _domain; }
        }

        public SafeFreeNtlmCredentials(string username, string password, string domain)
            : base(IntPtr.Zero, false)
        {
            _username = username;
            _password = password;
            _domain = domain;
        }

        public override bool IsInvalid
        {
            get { return false; }
        }

        protected override bool ReleaseHandle()
        {
            return true;
        }
    }

    internal sealed class SafeDeleteNtlmContext : SafeHandle
    {
        private readonly SafeFreeNtlmCredentials _credential;
        private readonly uint _flags;
        private Interop.libheimntlm.SafeNtlmKeyHandle _serverSignKey;
        private Interop.libheimntlm.SafeNtlmKeyHandle _serverSealKey;
        private Interop.libheimntlm.SafeNtlmKeyHandle _clientSignKey;
        private Interop.libheimntlm.SafeNtlmKeyHandle _clientSealKey;

        public uint Flags
        {
            get { return _flags;  }
        }

        public SafeDeleteNtlmContext(SafeFreeNtlmCredentials credential, uint flags)
            : base(IntPtr.Zero, true)
        {
            bool ignore = false;
            credential.DangerousAddRef(ref ignore);
            _credential = credential;
            _flags = flags;
        }

        public override bool IsInvalid
        {
            get { return (null == _credential) || _credential.IsInvalid; }
        }

        public void SetKeys(Interop.libheimntlm.SafeNtlmBufferHandle sessionKey)
        {
            Interop.HeimdalNtlm.CreateKeys(sessionKey, out _serverSignKey, out _serverSealKey, out _clientSignKey, out _clientSealKey);
        }

        public byte[] MakeSignature(bool isSend, byte[] buffer, int offset, int count)
        {
            if (isSend)
            {
                return _clientSignKey.Sign(_clientSealKey, buffer, offset, count);
            }
            else
            {
                return _serverSignKey.Sign(_serverSealKey, buffer, offset, count);
            }
        }

        public byte[] EncryptOrDecrypt(bool isEncrypt, byte[] buffer, int offset, int count)
        {
            if (isEncrypt)
            {
                return _clientSealKey.SealOrUnseal(true, buffer, offset, count);
            }
            else
            {
                return _serverSealKey.SealOrUnseal(false, buffer, offset, count);
            }
        }

        protected override bool ReleaseHandle()
        {
            _credential.DangerousRelease();
            if ((null != _clientSignKey) && !_clientSignKey.IsInvalid)
            {
                _clientSignKey.Dispose();
            }
            if ((null != _clientSealKey) && !_clientSealKey.IsInvalid)
            {
                _clientSealKey.Dispose();
            }
            if ((null != _serverSignKey) && !_serverSignKey.IsInvalid)
            {
                _serverSignKey.Dispose();
            }
            if ((null != _serverSealKey) && !_serverSealKey.IsInvalid)
            {
                _serverSealKey.Dispose();
            }
            return true;
        }
    }
}
