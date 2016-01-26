// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace System.Net.Security
{
    internal sealed partial class SafeFreeNegoCredentials : SafeFreeCredentials
    {
        public SafeFreeNegoCredentials(bool ntlmOnly, string username, string password, string domain) : base(IntPtr.Zero, true)
        {
            _isNtlm = ntlmOnly;
            _isDefault = string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password);
            _username = username;
            _domain = domain;
            _credential = SafeGssCredHandle.Create(username, password, domain);
        }
    }

    internal sealed partial class SafeDeleteNegoContext : SafeDeleteContext
    {
        public SafeDeleteNegoContext(SafeFreeNegoCredentials credential)
            : base(credential)
        {
            // Try to construct target in user@domain format
            string targetName = credential.UserName;
            if (!targetName.Contains("@") && !string.IsNullOrWhiteSpace(credential.Domain))
            {
                targetName += "@" + credential.Domain;
            }

            try
            {
                _targetName = SafeGssNameHandle.Create(targetName, true);
            }
            catch
            {
                base.ReleaseHandle();
                throw;
            }
        }

        public byte[] MakeSignature(bool isSend, byte[] buffer, int offset, int count)
        {
            throw new PlatformNotSupportedException();
        }

        public byte[] EncryptOrDecrypt(bool isEncrypt, byte[] buffer, int offset, int count)
        {
            throw new PlatformNotSupportedException();
        }
    }
}
