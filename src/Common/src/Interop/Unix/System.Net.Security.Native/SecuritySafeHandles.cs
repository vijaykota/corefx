// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.Win32.SafeHandles
{
    internal sealed class SafeFreeNegoCredentials : SafeFreeCredentials
    {
        private readonly SafeGssCredHandle _credential;
        private bool _isNtlm;

        public bool IsNTLM
        {
            get { return _isNtlm;  }
        }

        public SafeGssCredHandle GssCredential
        {
            get { return _credential; }
        }

        public SafeFreeNegoCredentials(bool isNtlm, string username, string password, string domain) : base(IntPtr.Zero, true)
        {
            _isNtlm = isNtlm;
            if (!_isNtlm)
            {
                _credential = new SafeGssCredHandle(username, password, domain);
                if (null != _credential)
                {
                    bool ignore = false;
                    _credential.DangerousAddRef(ref ignore);
                }
            }
        }

        public override bool IsInvalid
        {
            get { return (null == _credential) || _credential.IsInvalid; }
        }

        public override void Dispose(bool disposing)
        {
            if (disposing && (null != _credential))
            {
                _credential.Dispose();
            }
            base.Dispose(disposing);
        }

        protected override bool ReleaseHandle()
        {
            if (null != _credential)
            {
                _credential.DangerousRelease();
            }
            return true;
        }
    }

    internal sealed class SafeDeleteNegoContext : SafeDeleteContext
    {
        private SafeGssNameHandle _targetName;
        private SafeGssContextHandle _context;

        public SafeGssNameHandle TargetName
        {
            get { return _targetName; }
        }

        public SafeGssContextHandle GssContext
        {
            get { return _context; }
        }

        public SafeDeleteNegoContext(SafeFreeNegoCredentials credential, string targetName)
            : base(credential)
        {
            _targetName = new SafeGssNameHandle(targetName, false);
        }

        public override bool IsInvalid
        {
            get { return base.IsInvalid && (null == _context) && (null == _targetName); }
        }

        public void SetHandle(SafeGssContextHandle context)
        {
            Debug.Assert(!context.IsInvalid, "Invalid context passed to SafeDeleteNegoContext");
            _context = context;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_context != null)
                {
                    _context.Dispose();
                    _context = null;
                }
                _targetName.Dispose();
                _targetName = null;
            }
            base.Dispose(disposing);
        }

        protected override bool ReleaseHandle()
        {
            return base.ReleaseHandle();
        }
    }

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
