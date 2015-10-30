// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;

using size_t = System.IntPtr;

internal static partial class Interop
{
    internal static partial class libheimntlm
    {

        [StructLayout(LayoutKind.Sequential)]
        internal struct ntlm_buf
        {
            internal size_t length;
            internal IntPtr data;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct ntlm_type1
        {
            internal uint flags;
            internal uint padding;
            internal IntPtr domain;
            internal IntPtr hostname;
            internal fixed uint os[2];
        }

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct ntlm_type2
        {
            internal uint flags;
            internal uint padding;
            internal IntPtr targetname;
            internal ntlm_buf targetinfo;
            internal fixed byte challenge[8];
            internal fixed uint context[2];
            internal fixed uint os[2];
        }

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct ntlm_type3
        {
            internal uint flags;
            internal uint padding;
            internal IntPtr username;
            internal IntPtr targetname;
            internal ntlm_buf lm;
            internal ntlm_buf ntlm;
            internal ntlm_buf session_key;
            internal IntPtr ws;
            internal fixed uint os[2];
            internal size_t mic_offset;
            internal fixed byte mic [16];
        }

        internal partial class NtlmFlags
        {
            internal const uint NTLMSSP_NEGOTIATE_UNICODE = 0x1;
            internal const uint NTLMSSP_REQUEST_TARGET = 0x4;
            internal const uint NTLMSSP_NEGOTIATE_SIGN = 0x10;
            internal const uint NTLMSSP_NEGOTIATE_SEAL = 0x20;
            internal const uint NTLMSSP_NEGOTIATE_NTLM = 0x200;
            internal const uint NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x8000;
            internal const uint NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x80000;
            internal const uint NTLMSSP_NEGOTIATE_128 = 0x20000000;
            internal const uint NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000;
        }
    }
}
