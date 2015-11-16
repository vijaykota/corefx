// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using Microsoft.Win32.SafeHandles;

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

// SEE IMPLEMENTATION AT: https://github.com/rajansingh10/corefx/pull/2

internal static partial class Interop
{
    internal static partial class libgssapi
    {
        [FlagsAttribute]
        internal enum GssFlags : uint
        {
            GSS_C_DELEG_FLAG = 1,
            GSS_C_MUTUAL_FLAG = 2,
            GSS_C_REPLAY_FLAG = 4,
            GSS_C_SEQUENCE_FLAG = 8,
            GSS_C_CONF_FLAG = 16,
            GSS_C_INTEG_FLAG = 32,
            GSS_C_ANON_FLAG = 64,
            GSS_C_PROT_READY_FLAG = 128,
            GSS_C_TRANS_FLAG = 256,
            GSS_C_DCE_STYLE = 4096,
            GSS_C_IDENTIFY_FLAG = 8192,
            GSS_C_EXTENDED_ERROR_FLAG = 16384,
            GSS_C_DELEG_POLICY_FLAG = 32768
        }
    }

    internal static partial class libheimntlm
    {
        [FlagsAttribute]
        internal enum NtlmFlags : uint
        {
            NTLMSSP_NEGOTIATE_UNICODE = 0x1,
            NTLMSSP_REQUEST_TARGET = 0x4,
            NTLMSSP_NEGOTIATE_SIGN = 0x10,
            NTLMSSP_NEGOTIATE_SEAL = 0x20,
            NTLMSSP_NEGOTIATE_NTLM = 0x200,
            NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x8000,
            NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x80000,
            NTLMSSP_NEGOTIATE_128 = 0x20000000,
            NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000,
        }
    }

    internal static class GssApi
    {
        internal static bool EstablishSecurityContext(ref SafeGssContextHandle context, SafeGssCredHandle credential, SafeGssNameHandle targetName, uint inFlags, byte[] inputBuffer, out byte[] outputBuffer, out uint outFlags)
        {
            outputBuffer = null;
            outFlags = 0;
            return false;
        }

        internal static SafeGssBufferHandle Encrypt(SafeGssContextHandle context, bool encrypt, byte[] inputBuffer, int offset, int count)
        {
            return null;
        }

        internal static int Decrypt(SafeGssContextHandle context, byte[] inputBuffer, int offset, int count)
        {
            return 0;
        }

        internal static string GetSourceName(SafeGssContextHandle context)
        {
            return null;
        }
    }
    internal static class HeimdalNtlm
    {
        internal static byte[] CreateNegotiateMessage(uint flags)
        {
            return null;
        }

        internal static byte[] CreateAuthenticateMessage(uint flags, string username, string password, string domain,
            byte[] type2Data, int offset, int count, out SafeNtlmBufferHandle sessionKey)
        {
            sessionKey = null;
            return null;
        }

        internal static void CreateKeys(SafeNtlmBufferHandle sessionKey, out SafeNtlmKeyHandle serverSignKey, out SafeNtlmKeyHandle serverSealKey, out SafeNtlmKeyHandle clientSignKey, out SafeNtlmKeyHandle clientSealKey)
        {
            serverSignKey = null;
            serverSealKey = null;
            clientSignKey = null;
            clientSealKey = null;
        }
    }
}

namespace Microsoft.Win32.SafeHandles
{
    internal abstract class SafeNegoHandle : SafeHandle
    {
        protected SafeNegoHandle()
            : base(IntPtr.Zero, false)
        {
        }

        public override bool IsInvalid
        {
            get { return true; }
        }

        protected override bool ReleaseHandle()
        {
            Debug.Fail("Unexpected release of SafeNegoHandle");
            return false;
        }
    }

    internal class SafeGssBufferHandle : SafeNegoHandle
    {
        public int Length { get { return 0; } }
        public IntPtr Value { get { return IntPtr.Zero; } }
        public SafeGssBufferHandle()
            : base()
        {
        }
    }

    internal class SafeGssContextHandle : SafeNegoHandle
    {
        public SafeGssContextHandle() : base()
        {
        }
    }

    internal class SafeGssCredHandle : SafeNegoHandle
    {
        public SafeGssCredHandle(string username, string password, string domain)
            : base()
        {
        }
    }

    internal class SafeGssNameHandle : SafeNegoHandle
    {
        public SafeGssNameHandle(string name, bool isUser)
            : base()
        {
        }
    }

    internal class SafeNtlmBufferHandle : SafeNegoHandle
    {
        public SafeNtlmBufferHandle()
            : base()
        {
        }
    }

    internal class SafeNtlmKeyHandle : SafeNegoHandle
    {
        public SafeNtlmKeyHandle(SafeNtlmBufferHandle key, bool isClient, bool sign)
            : base()
        {
        }

        public byte[] Sign(SafeNtlmKeyHandle sealingKey, byte[] buffer, int offset, int count)
        {
            return null;
        }

        public byte[] SealOrUnseal(bool seal, byte[] buffer, int offset, int count)
        {
            return null;
        }
    }
}
