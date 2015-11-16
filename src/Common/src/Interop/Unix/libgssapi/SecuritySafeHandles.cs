// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Win32.SafeHandles;

using System.Diagnostics;
using System.Net.Security;
using System.Runtime.InteropServices;

namespace System.Net.Security
{
    internal sealed class SafeFreeGssCredentials : SafeFreeCredentials
    {
        private readonly SafeGssCredHandle _credential;

        public SafeGssCredHandle GssCredential
        {
            get { return _credential; }
        }

        public SafeFreeGssCredentials(string username, string password, string domain) : base(IntPtr.Zero, true)
        {
            _credential = new SafeGssCredHandle(username, password, domain);
            bool ignore = false;
            _credential.DangerousAddRef(ref ignore);
        }

        public override bool IsInvalid
        {
            get { return (null == _credential) || _credential.IsInvalid; }
        }

        protected override bool ReleaseHandle()
        {
            _credential.DangerousRelease();
            _credential.Dispose();  // TODO: Move to Dispose() override
            return true;
        }
    }

    internal sealed class SafeDeleteGssContext : SafeDeleteContext
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

        public SafeDeleteGssContext(SafeFreeGssCredentials credential, string targetName)
            : base(credential)
        {
            // In server case, targetName can be null or empty
            if (!String.IsNullOrEmpty(targetName))
            {
                _targetName = new SafeGssNameHandle(targetName, false);
            }
        }

        public override bool IsInvalid
        {
            // For server, target would be invalid but context may be valid
            get { return base.IsInvalid && (null == _targetName) && (null == _context); }
        }

        public void SetHandle(SafeGssContextHandle context)
        {
            Debug.Assert(!context.IsInvalid, "Invalid context passed to SafeDeleteGssContext");
            _context = context;
        }

        protected override bool ReleaseHandle()
        {
            if (_context != null)
            {
                _context.Dispose(); // TODO: Move to Dispose override
                _context = null;
            }
            if (_targetName != null)
            {
                _targetName.Dispose(); // TODO: Move to Dispose override
                _targetName = null;
            }
            return base.ReleaseHandle();
        }
    }
}
