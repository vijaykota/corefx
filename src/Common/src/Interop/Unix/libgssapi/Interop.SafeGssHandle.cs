// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

using OM_uint32 = System.UInt32;
using size_t = System.IntPtr;

internal static partial class Interop
{
    internal static partial class libgssapi
    {
        /// <summary>
        /// Wrapper around a gss_buffer_desc*
        /// </summary>
        internal sealed class SafeGssBufferHandle : SafeHandle
        {
            private int _length;
            private IntPtr _value;

            // Return the buffer size
            public int Length
            {
                get
                {
                    if (IsInvalid)
                    {
                        return 0;
                    }
                    _length = Marshal.ReadInt32(handle);
                    return _length;
                }
            }

            // Return a pointer to where data resides
            public IntPtr Value
            {
                get
                {
                    if (IsInvalid)
                    {
                        return IntPtr.Zero;
                    }
                    _value = Marshal.ReadIntPtr(handle, (int)Marshal.OffsetOf<gss_buffer_desc>("value"));
                    return _value;
                }
            }

            public SafeGssBufferHandle() : this(0, IntPtr.Zero)
            {
            }

            public SafeGssBufferHandle(int length, IntPtr value) : base(IntPtr.Zero, length==0)
            {
                _length = length;
                _value = value;
                gss_buffer_desc buffer = new gss_buffer_desc
                    {
                        length = (size_t)_length,
                        value = _value,
                    };
                handle = Marshal.AllocHGlobal(Marshal.SizeOf<gss_buffer_desc>());
                Marshal.StructureToPtr(buffer, handle, false);
            }

            public override bool IsInvalid
            {
                get { return handle == IntPtr.Zero; }
            }

            // Note that _value should never be freed directly. For input
            // buffer, it is owned by the caller and for output buffer,
            // it is owned by libgssapi
            protected override bool ReleaseHandle()
            {
                if (_value == IntPtr.Zero)
                {
                    _value = Marshal.ReadIntPtr(handle, (int)Marshal.OffsetOf<gss_buffer_desc>("value"));
                }
                if (_value != IntPtr.Zero)
                {
                    OM_uint32 status, minorStatus;
                    status = gss_release_buffer(out minorStatus, handle);
                    GssApiException.AssertOrThrowIfError("gss_release_buffer failed", status, minorStatus);
                }
                Marshal.FreeHGlobal(handle);
                SetHandle(IntPtr.Zero);
                return true;
            }
        }

        /// <summary>
        /// Wrapper around a gss_name_t_desc*
        /// </summary>
        internal sealed class SafeGssNameHandle : SafeHandle
        {
            public SafeGssNameHandle(string name, gss_OID_desc type) : base(IntPtr.Zero, true)
            {
                Debug.Assert(!String.IsNullOrEmpty(name), "Invalid name passed to SafeGssNameHandle");
                IntPtr namePtr = Marshal.StringToHGlobalAnsi(name);
                try
                {
                    using (SafeGssBufferHandle buffer = new SafeGssBufferHandle(name.Length, namePtr))
                    {
                        OM_uint32 status, minorStatus;
                        status = gss_import_name(out minorStatus, buffer, ref type, ref handle);
                        GssApiException.AssertOrThrowIfError("gss_import_name failed", status, minorStatus);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(namePtr);
                }
            }

            public override bool IsInvalid
            {
                get { return handle == IntPtr.Zero; }
            }

            protected override bool ReleaseHandle()
            {
                OM_uint32 status, minorStatus;
                status = gss_release_name(out minorStatus, ref handle);
                GssApiException.AssertOrThrowIfError("gss_release_name failed", status, minorStatus);
                return true;
            }

            private SafeGssNameHandle() : base (IntPtr.Zero, true)
            {
            }
        }

        /// <summary>
        /// Wrapper around a gss_cred_id_t_desc_struct*
        /// </summary>
        internal class SafeGssCredHandle : SafeHandle
        {
            private static gss_OID_set_desc s_spnegoSet = new gss_OID_set_desc
                {
                    count = (size_t)1,
                    elements = GCHandle.Alloc(GSS_SPNEGO_MECHANISM, GCHandleType.Pinned).AddrOfPinnedObject(),
                };

            public SafeGssCredHandle(string username, string password, string domain) : base(IntPtr.Zero, true)
            {
                // Empty username is OK if Kerberos ticket was already obtained
                if (!String.IsNullOrEmpty(username))
                {
                    using (SafeGssNameHandle userHandle = new SafeGssNameHandle(username, GSS_C_NT_USER_NAME))
                    {
                        OM_uint32 status, minorStatus, outTime;
                        if (String.IsNullOrEmpty(password))
                        {
                            status = gss_acquire_cred(out minorStatus, userHandle, 0, ref s_spnegoSet,
                                    gss_cred_usage_t.GSS_C_INITIATE, ref handle, SafeGssHandle.Instance, out outTime);
                            GssApiException.AssertOrThrowIfError("gss_acquire_cred failed", status, minorStatus);
                        }
                        else
                        {
                            IntPtr passwordPtr = Marshal.StringToHGlobalAnsi(password);
                            try
                            {
                                using (SafeGssBufferHandle buffer = new SafeGssBufferHandle(password.Length, passwordPtr))
                                {
                                    status = gss_acquire_cred_with_password(out minorStatus, userHandle, buffer, 0, ref s_spnegoSet,
                                            gss_cred_usage_t.GSS_C_INITIATE, ref handle, SafeGssHandle.Instance, out outTime);
                                    GssApiException.AssertOrThrowIfError("gss_acquire_cred_with_password failed", status, minorStatus);
                                }
                            }
                            finally
                            {
                                Marshal.FreeHGlobal(passwordPtr);
                            }
                        }
                    }
                }
            }

            public override bool IsInvalid
            {
                get { return handle == IntPtr.Zero; }
            }

            protected override bool ReleaseHandle()
            {
                OM_uint32 status, minorStatus;
                status = gss_release_cred(out minorStatus, ref handle);
                GssApiException.AssertOrThrowIfError("gss_release_cred failed", status, minorStatus);
                return true;
            }
        }

        internal sealed class SafeGssContextHandle : SafeHandle
        {
            public SafeGssContextHandle() : base(IntPtr.Zero, true)
            {
            }

            public override bool IsInvalid
            {
                get { return handle == IntPtr.Zero; }
            }

            protected override bool ReleaseHandle()
            {
                OM_uint32 status, minorStatus;
                status = gss_delete_sec_context(out minorStatus, ref handle, new SafeGssBufferHandle());
                GssApiException.AssertOrThrowIfError("gss_delete_sec_context failed", status, minorStatus);
                return true;
            }
        }

        /// <summary>
        /// Generic handle to wrap an IntPtr.Zero in p/invokes
        /// Use SafeGssHandle.Instance for all p/invoke parameters
        /// expecting a SafeGssHandle
        /// </summary>
        internal class SafeGssHandle : SafeHandle
        {
            internal static readonly SafeGssHandle Instance = new SafeGssHandle();

            private SafeGssHandle() : base (IntPtr.Zero, false)
            {
            }

            public override bool IsInvalid
            {
                get { return true; }
            }

            protected override bool ReleaseHandle()
            {
                Debug.Fail("Unexpected release of SafeGssHandle");
                return false;
            }
        }
    }
}
