using System;
using System.Security.Authentication;
using System.Threading.Tasks;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;

namespace System.Net.Security.Tests
{
    public partial class KDCSetup
    {
        public static bool CheckAndInitializeNtlm(bool isKrbAvailable)
        {
            return isKrbAvailable;
        }
    }

    internal partial class UnixGssFakeNegotiateStream : NegotiateStream
    {
        private static bool EstablishSecurityContext(
            ref SafeGssContextHandle context,
            ref bool isNtlm,
            byte[] buffer,
            out byte[] outputBuffer)
        {
            outputBuffer = null;

            // EstablishSecurityContext is called multiple times in a session.
            // In each call, we need to pass the context handle from the previous call.
            // For the first call, the context handle will be null.
            if (context == null)
            {
                context = new SafeGssContextHandle();
            }

            Interop.NetSecurityNative.GssBuffer token = default(Interop.NetSecurityNative.GssBuffer);
            Interop.NetSecurityNative.Status status;

            try
            {
                status = Interop.NetSecurityNative.AcceptSecContext(out minorStatus,
                                                          ref context,
                                                          buffer,
                                                          (buffer == null) ? 0 : buffer.Length,
                                                          ref token);

                if ((status != Interop.NetSecurityNative.Status.GSS_S_COMPLETE) && (status != Interop.NetSecurityNative.Status.GSS_S_CONTINUE_NEEDED))
                {
                    throw new Interop.NetSecurityNative.GssApiException(status, minorStatus);
                }

                outputBuffer = token.ToByteArray();
            }
            finally
            {
                token.Dispose();
            }

            return status == Interop.NetSecurityNative.Status.GSS_S_COMPLETE;
        }

        private static byte[] UnwrapMessage(SafeGssContextHandle context, byte[] message)
        {
            Interop.NetSecurityNative.GssBuffer unwrapped = default(Interop.NetSecurityNative.GssBuffer);
            Interop.NetSecurityNative.Status status;

            try
            {
                Interop.NetSecurityNative.Status minorStatus;
                status = Interop.NetSecurityNative.Unwrap(out minorStatus,
                                                          context,
                                                          message,
                                                          0,
                                                          message.Length,
                                                          ref unwrapped);
                if (status != Interop.NetSecurityNative.Status.GSS_S_COMPLETE)
                {
                    throw new Interop.NetSecurityNative.GssApiException(status, minorStatus);
                }

                return unwrapped.ToByteArray();
            }
            finally
            {
                unwrapped.Dispose();
            }
        }

        private static byte[] WrapMessage(SafeGssContextHandle context, byte[] message)
        {
            Interop.NetSecurityNative.GssBuffer wrapped = default(Interop.NetSecurityNative.GssBuffer);
            Interop.NetSecurityNative.Status status;

            try
            {
                Interop.NetSecurityNative.Status minorStatus;
                status = Interop.NetSecurityNative.Wrap(out minorStatus,
                                                        context,
                                                        false,
                                                        message,
                                                        0,
                                                        message.Length,
                                                        ref wrapped);
                if (status != Interop.NetSecurityNative.Status.GSS_S_COMPLETE)
                {
                    throw new Interop.NetSecurityNative.GssApiException(status, minorStatus);
                }

                return wrapped.ToByteArray();
            }
            finally
            {
                wrapped.Dispose();
            }
        }
    }
}


