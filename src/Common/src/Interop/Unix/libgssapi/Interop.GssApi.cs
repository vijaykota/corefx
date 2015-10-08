// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

using SafeGssHandle = Interop.libgssapi.SafeGssHandle;
using SafeGssBufferHandle = Interop.libgssapi.SafeGssBufferHandle;
using SafeGssNameHandle = Interop.libgssapi.SafeGssNameHandle;
using SafeGssCredHandle = Interop.libgssapi.SafeGssCredHandle;
using SafeGssContextHandle = Interop.libgssapi.SafeGssContextHandle;
using OM_uint32 = System.UInt32;

internal static partial class Interop
{
    internal static class GssApi
    {
        internal static bool EstablishSecurityContext(
            ref SafeGssContextHandle context,
            SafeGssCredHandle credential,
            SafeGssNameHandle targetName,
            OM_uint32 inFlags,
            byte[] inputBuffer,
            out byte[] outputBuffer,
            out OM_uint32 outFlags)
        {
            outputBuffer = null;
            outFlags = 0;

            if (context == null)
            {
                context = new SafeGssContextHandle();
            }

            unsafe
            {
                fixed (byte* bytePtr = inputBuffer)
                {
                    int inputSize = (inputBuffer == null) ? 0 : inputBuffer.Length;
                    IntPtr inputPtr = (inputSize == 0) ? IntPtr.Zero : new IntPtr(bytePtr);

                    using (SafeGssBufferHandle inputToken = new SafeGssBufferHandle(inputSize, inputPtr))
                    using (SafeGssBufferHandle outputToken = new SafeGssBufferHandle())
                    {
                        OM_uint32 status, minorStatus, outTime;

                        if (targetName == null)
                        {
                            status = libgssapi.gss_accept_sec_context(
                                         out minorStatus,
                                         ref context,
                                         credential,
                                         inputToken,
                                         SafeGssHandle.Instance,
                                         SafeGssHandle.Instance,
                                         SafeGssHandle.Instance,
                                         outputToken,
                                         out outFlags,
                                         out outTime,
                                         SafeGssHandle.Instance);
                        }
                        else
                        {
                            status = libgssapi.gss_init_sec_context(
                                         out minorStatus,
                                         credential,
                                         ref context,
                                         targetName,
                                         ref libgssapi.GSS_SPNEGO_MECHANISM,
                                         inFlags,
                                         0,
                                         SafeGssHandle.Instance,
                                         inputToken,
                                         SafeGssHandle.Instance,
                                         outputToken,
                                         out outFlags,
                                         out outTime);
                        }

                        if ((status != libgssapi.Status.GSS_S_COMPLETE) && (status != libgssapi.Status.GSS_S_CONTINUE_NEEDED))
                        {
                            throw libgssapi.GssApiException.Create(SR.net_context_establishment_failed, status, minorStatus);
                        }

                        outputBuffer = new byte[outputToken.Length]; // Always return non-null
                        if (outputToken.Length > 0)
                        {
                            Marshal.Copy(outputToken.Value, outputBuffer, 0, outputToken.Length);
                        }

                        return (status == libgssapi.Status.GSS_S_COMPLETE) ? true : false;
                    }
                }
            }
        }

        internal static int Encrypt(
            SafeGssContextHandle context,
            bool encrypt,
            byte[] inputBuffer,
            int offset,
            int count,
            out byte[] outputBuffer)
        {
            outputBuffer = null;
            Debug.Assert((inputBuffer != null) && (inputBuffer.Length > 0), "Invalid input buffer passed to Encrypt");
            Debug.Assert((offset >= 0) && (offset < inputBuffer.Length), "Invalid input offset passed to Encrypt");
            Debug.Assert((count > 0) && (count <= (inputBuffer.Length - offset)), "Invalid input count passed to Encrypt");

            unsafe
            {
                fixed (byte* bytePtr = inputBuffer)
                {
                    using (SafeGssBufferHandle inputToken = new SafeGssBufferHandle(count, new IntPtr(bytePtr + offset)))
                    using (SafeGssBufferHandle outputToken = new SafeGssBufferHandle())
                    {
                        OM_uint32 status, minorStatus;
                        int outConf;
                        int inConf = encrypt ? 1 : 0;

                        status = libgssapi.gss_wrap(out minorStatus, context, inConf, libgssapi.GSS_C_QOP_DEFAULT, inputToken, out outConf, outputToken);
                        if (status != libgssapi.Status.GSS_S_COMPLETE)
                        {
                            throw libgssapi.GssApiException.Create(SR.net_context_wrap_failed, status, minorStatus);
                        }
                        Debug.Assert((outConf == 0) == (inConf == 0), "Encryption/signing failed. Expected: " + inConf + " Actual: " + outConf);

                        outputBuffer = new byte[outputToken.Length]; // Always return non-null
                        if (outputToken.Length > 0)
                        {
                            Marshal.Copy(outputToken.Value, outputBuffer, 0, outputToken.Length);
                        }
                        return outputBuffer.Length;
                    }
                }
            }
        }

        internal static int Decrypt(
            SafeGssContextHandle context,
            byte[] inputBuffer,
            int offset,
            int count)
        {
            Debug.Assert((inputBuffer != null) && (inputBuffer.Length > 0), "Invalid input buffer passed to Decrypt");
            Debug.Assert((offset >= 0) && (offset < inputBuffer.Length), "Invalid input offset passed to Decrypt");
            Debug.Assert((count > 0) && (count <= (inputBuffer.Length - offset)), "Invalid input count passed to Decrypt");

            unsafe
            {
                fixed (byte* bytePtr = inputBuffer)
                {
                    using (SafeGssBufferHandle inputToken = new SafeGssBufferHandle(count, new IntPtr(bytePtr + offset)))
                    using (SafeGssBufferHandle outputToken = new SafeGssBufferHandle())
                    {
                        OM_uint32 status, minorStatus, outQOP;
                        int outConf;

                        status = libgssapi.gss_unwrap(out minorStatus, context, inputToken, outputToken, out outConf, out outQOP);
                        if (status != libgssapi.Status.GSS_S_COMPLETE)
                        {
                            throw libgssapi.GssApiException.Create(SR.net_context_unwrap_failed, status, minorStatus);
                        }

                        if (outputToken.Length > inputBuffer.Length)
                        {
                            throw libgssapi.GssApiException.Create(SR.Format(SR.net_context_buffer_too_small, outputToken.Length, inputBuffer.Length));
                        }

                        if (outputToken.Length > 0)
                        {
                            Marshal.Copy(outputToken.Value, inputBuffer, 0, outputToken.Length);
                        }
                        return outputToken.Length;
                    }
                }
            }
        }

        internal static string GetSourceName(SafeGssContextHandle context)
        {
            OM_uint32 status, minorStatus, lifetime, contextFlags;
            int localContext, openContext;
            SafeGssNameHandle sourceName;

            status = libgssapi.gss_inquire_context(
                         out minorStatus,
                         context,
                         out sourceName,
                         SafeGssHandle.Instance,
                         out lifetime,
                         SafeGssHandle.Instance,
                         out contextFlags,
                         out localContext,
                         out openContext);
            if (status != libgssapi.Status.GSS_S_COMPLETE)
            {
                throw libgssapi.GssApiException.Create(status, minorStatus);
            }

            try
            {
                using (SafeGssBufferHandle outputBuffer = new SafeGssBufferHandle())
                {
                    status = libgssapi.gss_display_name(out minorStatus, sourceName, outputBuffer, SafeGssHandle.Instance);
                    if (status != libgssapi.Status.GSS_S_COMPLETE)
                    {
                        throw libgssapi.GssApiException.Create(status, minorStatus);
                    }

                    // String may not be NULL terminated so PtrToStringAnsi cannot be used
                    unsafe
                    {
                        return Encoding.UTF8.GetString((byte*)outputBuffer.Value.ToPointer(), outputBuffer.Length);
                    }
                }
            }
            finally
            {
                sourceName.Dispose();
            }
        }
    }
}
