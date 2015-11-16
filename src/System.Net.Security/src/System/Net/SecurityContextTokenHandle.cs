// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Win32.SafeHandles;

using System.Threading;

namespace System.Net.Security
{
#if DEBUG
    internal sealed class SecurityContextTokenHandle : DebugSafeHandle
    {
#else
    internal sealed class SecurityContextTokenHandle : SafeHandle
    {
#endif
        private int _disposed;

        private SecurityContextTokenHandle() : base(IntPtr.Zero, true)
        {
        }

        public override bool IsInvalid
        {
            get { return (handle == IntPtr.Zero) || (handle == new IntPtr(-1)); }
        }

        protected override bool ReleaseHandle()
        {
            return Interop.mincore.CloseHandle(handle);
        }
    }
}
