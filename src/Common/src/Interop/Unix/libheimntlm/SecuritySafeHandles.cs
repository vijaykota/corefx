// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Win32.SafeHandles;

using System.Diagnostics;
using System.Net.Security;
using System.Runtime.InteropServices;

namespace System.Net.Security
{
    internal sealed class SafeFreeNtlmCredentials : SafeFreeCredentials
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
            : base(IntPtr.Zero, true)
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

    internal sealed class SafeDeleteNtlmContext : SafeDeleteContext
    {
        private readonly Interop.libheimntlm.NtlmFlags _flags;
        private SafeNtlmKeyHandle _serverSignKey;
        private SafeNtlmKeyHandle _serverSealKey;
        private SafeNtlmKeyHandle _clientSignKey;
        private SafeNtlmKeyHandle _clientSealKey;

        public Interop.libheimntlm.NtlmFlags Flags
        {
            get { return _flags;  }
        }

        public SafeDeleteNtlmContext(SafeFreeNtlmCredentials credential, Interop.libheimntlm.NtlmFlags flags)
            : base(credential)
        {
            _flags = flags;
        }

        public override bool IsInvalid
        {
            get { return base.IsInvalid && (null == _serverSignKey) && (null == _serverSealKey) && (null == _clientSignKey) && (null == _clientSealKey); }
        }

        public void SetKeys(SafeNtlmBufferHandle sessionKey)
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
            return base.ReleaseHandle();
        }
    }
}
