// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace System.Net.Security
{
    internal sealed partial class SafeFreeNegoCredentials : SafeFreeCredentials
    {
        private readonly string _password;

        public string Password
        {
            get { return _password; }
        }

        public SafeFreeNegoCredentials(bool ntlmOnly, string username, string password, string domain) : base(IntPtr.Zero, true)
        {
            _isNtlm = ntlmOnly;
            _isDefault = string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password);
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
                    Console.WriteLine("***** vijayko CRED FALL BACK ****");
                    _isNtlm = true;
                }
            }

            // Even if Kerberos creds could be obtained, we might later need
            // to fall back to NTLM if service ticket cannot be fetched
            _username = username;
            _password = password;
            _domain = domain;
        }
    }

    internal sealed partial class SafeDeleteNegoContext : SafeDeleteContext
    {
        private readonly Interop.NetSecurity.NtlmFlags _flags;
        private SafeNtlmKeyHandle _serverSignKey;
        private SafeNtlmKeyHandle _serverSealKey;
        private SafeNtlmKeyHandle _clientSignKey;
        private SafeNtlmKeyHandle _clientSealKey;

        public Interop.NetSecurity.NtlmFlags Flags
        {
            get { return _flags; }
        }

        public SafeDeleteNegoContext(SafeFreeNegoCredentials credential, Interop.NetSecurity.NtlmFlags flags)
            : base(credential)
        {
            _flags = flags;
            _isNtlm = true;
        }

        public void SetKeys(SafeNtlmBufferHandle sessionKey)
        {
            Interop.NetSecurity.CreateKeys(sessionKey, out _serverSignKey, out _serverSealKey, out _clientSignKey, out _clientSealKey);
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
    }
}
