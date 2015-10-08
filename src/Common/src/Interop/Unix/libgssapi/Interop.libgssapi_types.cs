// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;

using OM_uint32 = System.UInt32;
using size_t = System.IntPtr;

internal static partial class Interop
{
    internal static partial class libgssapi
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct gss_buffer_desc
        {
            internal size_t length;
            internal IntPtr value;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct gss_OID_desc
        {
            internal OM_uint32 length;
            internal uint padding;
            internal IntPtr elements;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct gss_OID_set_desc
        {
            internal size_t count;
            internal IntPtr elements;
        }

        internal partial class Status
        {
            internal const OM_uint32 GSS_S_COMPLETE = 0;
            internal const OM_uint32 GSS_S_CONTINUE_NEEDED = 1;
        }

        internal partial class StatusType
        {
            internal const int GSS_C_GSS_CODE = 1;
            internal const int GSS_C_MECH_CODE = 2;
        }

        [FlagsAttribute]
        internal enum ContextFlags : uint
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

        internal static partial class gss_cred_usage_t
        {
            internal const int GSS_C_INITIATE = 1;
        }

        internal const OM_uint32 GSS_C_QOP_DEFAULT = 0;

        internal static gss_OID_desc GSS_C_NT_USER_NAME = new gss_OID_desc
            {
                length = 10,
                padding = 0,
                elements = GCHandle.Alloc(new byte[] {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x01}, GCHandleType.Pinned).AddrOfPinnedObject(),
            };

        internal static gss_OID_desc GSS_KRB5_NT_PRINCIPAL_NAME = new gss_OID_desc
            {
                length = 10,
                padding = 0,
                elements = GCHandle.Alloc(new byte[] {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x01}, GCHandleType.Pinned).AddrOfPinnedObject(),
            };

        internal static gss_OID_desc GSS_SPNEGO_MECHANISM = new gss_OID_desc
            {
                length = 6,
                padding = 0,
                elements = GCHandle.Alloc(new byte[] {0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}, GCHandleType.Pinned).AddrOfPinnedObject(),
            };
    }
}
