// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using OM_uint32 = System.UInt32;

internal static partial class Interop
{
    internal static partial class libgssapi
    {
        internal sealed class GssApiException : Exception
        {
            private OM_uint32 _minorStatus;

            public OM_uint32 MinorStatus
            {
                get { return _minorStatus;  }
            }

            public GssApiException(string message) : base(message)
            {
            }

            public GssApiException(OM_uint32 majorStatus, OM_uint32 minorStatus)
                : base(SR.Format(SR.net_generic_operation_failed, majorStatus, minorStatus))
            {
                HResult = (int)majorStatus;
                _minorStatus = minorStatus;
            }

            public GssApiException(string message, OM_uint32 majorStatus, OM_uint32 minorStatus)
                : base(message)
            {
                HResult = (int)majorStatus;
                _minorStatus = minorStatus;
            }


            public static GssApiException Create(string message)
            {
                return new GssApiException(message);
            }

            public static GssApiException Create(OM_uint32 majorStatus, OM_uint32 minorStatus)
            {
                return new GssApiException(majorStatus, minorStatus);
            }

            public static GssApiException Create(string message, OM_uint32 majorStatus, OM_uint32 minorStatus)
            {
                return new GssApiException(SR.Format(message, majorStatus, minorStatus), majorStatus, minorStatus);
            }

            public static void AssertOrThrowIfError(string message, OM_uint32 majorStatus, OM_uint32 minorStatus)
            {
                if (majorStatus != Status.GSS_S_COMPLETE)
                {
                    var ex = Create(majorStatus, minorStatus);
                    Debug.Fail(message + ": " + ex);
                    throw ex;
                }
            }

#if DEBUG
            public override string ToString()
            {
                return Message + "\n GSSAPI status: " + GetGssApiDisplayStatus((OM_uint32)HResult, _minorStatus);
            }

            private static string GetGssApiDisplayStatus(OM_uint32 majorStatus, OM_uint32 minorStatus)
            {
                OM_uint32[] statusArr = new OM_uint32[] { majorStatus, minorStatus };
                int[] msgTypes = new int[] { StatusType.GSS_C_GSS_CODE, StatusType.GSS_C_MECH_CODE };
                string[] msgStrings = new string[2];

                for (int i = 0; i < msgTypes.Length; i++)
                {
                    using (SafeGssBufferHandle msgBuffer = new SafeGssBufferHandle())
                    {
                        OM_uint32 minStat, msgCtx = 0;
                        if (Status.GSS_S_COMPLETE != gss_display_status(out minStat, statusArr[i], msgTypes[i], SafeGssHandle.Instance, ref msgCtx, msgBuffer))
                        {
                            continue;
                        }
                        msgStrings[i] = Marshal.PtrToStringAnsi(msgBuffer.Value);
                    }
                }
                return msgStrings[0] + " (" + msgStrings[1] + ") + Status: " + majorStatus.ToString("x8") + " (" + minorStatus.ToString("x8") + ")";
            }
        }
    }
#endif
}
