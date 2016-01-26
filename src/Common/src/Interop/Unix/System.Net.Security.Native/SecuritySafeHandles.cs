// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace System.Net.Security
{
    internal sealed partial class SafeFreeNegoCredentials : SafeFreeCredentials
    {
        private SafeGssCredHandle _credential;
        private readonly string _username;
        private readonly string _domain;
        private bool _isNtlm;
        private bool _isDefault;

        public SafeGssCredHandle GssCredential
        {
            get { return _credential; }
        }

        public override bool IsInvalid
        {
            get { return (null == _credential); }
        }

        public string UserName
        {
            get { return _username; }
        }

        public string Domain
        {
            get { return _domain; }
        }

        public bool IsNTLM
        {
            get { return _isNtlm; }
        }

        public bool IsDefault
        {
            get { return _isDefault; }
        }

        protected override bool ReleaseHandle()
        {
            _credential.Dispose();
            _credential = null;
            return true;
        }
    }

    internal sealed partial class SafeDeleteNegoContext : SafeDeleteContext
    {
        private SafeGssNameHandle _targetName;
        private SafeGssContextHandle _context;
        private bool _isNtlm;

        public SafeGssNameHandle TargetName
        {
            get { return _targetName; }
        }

        public SafeGssContextHandle GssContext
        {
            get { return _context; }
        }

        public bool IsNTLM
        {
            get { return _isNtlm; }
        }

        public SafeDeleteNegoContext(SafeFreeNegoCredentials credential, string targetName)
            : base(credential)
        {
            try
            {
                _targetName = SafeGssNameHandle.Create(targetName, false);
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
    }
}

namespace Microsoft.Win32.SafeHandles
{

    /// <summary>
    /// Wrapper around an output gss_buffer_desc*
    /// </summary>
    internal sealed class SafeGssBufferHandle : SafeHandle
    {
        public SafeGssBufferHandle() : base(IntPtr.Zero, true)
        {
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        protected override bool ReleaseHandle()
        {
            if (handle != IntPtr.Zero)
            {
                Interop.NetSecurity.Status minorStatus;
                Interop.NetSecurity.Status status = Interop.NetSecurity.ReleaseBuffer(out minorStatus, handle);
                return status == Interop.NetSecurity.Status.GSS_S_COMPLETE;
            }

            SetHandle(IntPtr.Zero);
            return true;
        }
    }

    /// <summary>
    /// Wrapper around a gss_name_t_desc*
    /// </summary>
    internal sealed class SafeGssNameHandle : SafeHandle
    {
        public static SafeGssNameHandle Create(string name, bool isUser)
        {
            Debug.Assert(!string.IsNullOrEmpty(name), "Invalid name passed to SafeGssNameHandle create");
            SafeGssNameHandle retHandle;
            Interop.NetSecurity.Status minorStatus;
            Interop.NetSecurity.Status status = isUser?
                Interop.NetSecurity.ImportUserName(out minorStatus, name, name.Length, out retHandle) :
                Interop.NetSecurity.ImportPrincipalName(out minorStatus, name, name.Length, out retHandle);
            if (status != Interop.NetSecurity.Status.GSS_S_COMPLETE)
            {
                throw new Interop.NetSecurity.GssApiException(status, minorStatus);
            }

            return retHandle;
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        protected override bool ReleaseHandle()
        {
            Interop.NetSecurity.Status minorStatus;
            Interop.NetSecurity.Status status = Interop.NetSecurity.ReleaseName(out minorStatus, ref handle);
            Interop.NetSecurity.GssApiException.AssertOrThrowIfError("GssReleaseName failed", status, minorStatus);
            SetHandle(IntPtr.Zero);
            return true;
        }

        private SafeGssNameHandle()
            : base(IntPtr.Zero, true)
        {
        }
    }

    /// <summary>
    /// Wrapper around a gss_cred_id_t_desc_struct*
    /// </summary>
    internal class SafeGssCredHandle : SafeHandle
    {
        public static SafeGssCredHandle Create(string username, string password, string domain)
        {
            SafeGssCredHandle retHandle = null;

            // Empty username is OK if Kerberos ticket was already obtained
            if (!string.IsNullOrEmpty(username))
            {
                using (SafeGssNameHandle userHandle = SafeGssNameHandle.Create(username, true))
                {
                    Interop.NetSecurity.Status status;
                    Interop.NetSecurity.Status minorStatus;
                    if (string.IsNullOrEmpty(password))
                    {
                        status = Interop.NetSecurity.AcquireCredSpNego(out minorStatus, userHandle, true, out retHandle);
                    }
                    else
                    {
                        status = Interop.NetSecurity.AcquireCredWithPassword(out minorStatus, userHandle, password, password.Length, true, out retHandle);
                    }

                    if (status != Interop.NetSecurity.Status.GSS_S_COMPLETE)
                    {
                        throw new Interop.NetSecurity.GssApiException(status, minorStatus);
                    }
                }
            }

            return retHandle;
        }

        private SafeGssCredHandle()
            : base(IntPtr.Zero, true)
        {
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        protected override bool ReleaseHandle()
        {
            Interop.NetSecurity.Status minorStatus;
            Interop.NetSecurity.Status status = Interop.NetSecurity.ReleaseCred(out minorStatus, ref handle);
            Interop.NetSecurity.GssApiException.AssertOrThrowIfError("GssReleaseCred failed", status, minorStatus);
            SetHandle(IntPtr.Zero);
            return true;
        }
    }

    internal sealed class SafeGssContextHandle : SafeHandle
    {
        public SafeGssContextHandle()
            : base(IntPtr.Zero, true)
        {
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        protected override bool ReleaseHandle()
        {
            Interop.NetSecurity.Status minorStatus;
            Interop.NetSecurity.Status status = Interop.NetSecurity.DeleteSecContext(out minorStatus, ref handle);
            Interop.NetSecurity.GssApiException.AssertOrThrowIfError("GssDeleteSecContext failed", status, minorStatus);
            SetHandle(IntPtr.Zero);
            return true;
        }
    }
}
