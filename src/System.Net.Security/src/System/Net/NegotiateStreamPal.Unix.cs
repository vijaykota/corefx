// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Net.Security;
using System.Runtime.InteropServices;

namespace System.Net
{
    // Depending on PAL refactoring, this will either be part of a class that implements
    // SSPIInterfaceNego or Unix-specific files (eg. _NTAuthenticationPal.Unix.cs) will 
    // call into methods of this class
    internal static class NegotiateStreamPal
    {
        public static SecurityStatus AcquireCredentialsHandle(
            string moduleName,
            bool isInBoundCred,
            string username,
            string password,
            string domain,
            out SafeFreeGssCredentials outCredential)
        {
            if (isInBoundCred || string.IsNullOrEmpty(username))
            {
                // In server case, only the keytab file (eg. /etc/krb5.keytab) is used
                // In client case, equivalent of default credentials is to use previous,
                // unexpired Kerberos TGT to get service-specific ticket.
                outCredential = new SafeFreeGssCredentials(string.Empty, string.Empty, string.Empty);
            }
            else
            {
                outCredential = new SafeFreeGssCredentials(username, password, domain);
            }
            return SecurityStatus.OK;
        }

        public static SecurityStatus AcquireDefaultCredential(string moduleName, bool isInBoundCred, out SafeFreeGssCredentials outCredential)
        {
            return AcquireCredentialsHandle(moduleName, isInBoundCred, string.Empty, string.Empty, string.Empty, out outCredential);
        }

        public static SecurityStatus AcceptSecurityContext(
            SafeFreeGssCredentials credential,
            ref SafeDeleteGssContext context,
            SecurityBuffer inputBuffer,
            uint inFlags,
            uint endianNess,
            SecurityBuffer outputBuffer,
            ref uint outFlags)
        {
            return EstablishSecurityContext(credential, ref context, string.Empty, inFlags, inputBuffer, outputBuffer, ref outFlags);
        }

        public static SecurityStatus InitializeSecurityContext(
            SafeFreeGssCredentials credential,
            ref SafeDeleteGssContext context,
            string targetName,
            uint inFlags,
            uint endianNess,
            SecurityBuffer[] inputBuffers,
            SecurityBuffer outputBuffer,
            ref uint outFlags)
        {
            // TODO (Issue #3718): The second buffer can contain a channel binding which is not yet supported
            if (inputBuffers.Length > 1)
            {
                throw new NotImplementedException("No support for channel binding on non-Windows");
            }
            return EstablishSecurityContext(credential, ref context, targetName, inFlags, inputBuffers[0], outputBuffer, ref outFlags);
        }

        public static int EncryptOrSignMessage(SafeDeleteGssContext securityContext, byte[] buffer, int offset, int count, ref byte[] output, uint sequenceNumber)
        {
            // Sequence number is not used by libgssapi
            return Interop.GssApi.Encrypt(securityContext.GssContext, securityContext.NeedsEncryption, buffer, offset, count, out output);
        }

        public static int DecryptOrVerifyMessage(SafeDeleteGssContext securityContext, byte[] buffer, int offset, int count, out int newOffset, uint sequenceNumber)
        {
            // Sequence number is not used by libgssapi
            count = Interop.GssApi.Decrypt(securityContext.GssContext, buffer, offset, count);
            newOffset = 0;
            return count;
        }

        public static object QueryContextAttributes(SafeDeleteGssContext context, uint attribute, out SecurityStatus errorCode)
        {
            errorCode = SecurityStatus.OK;
            switch (attribute)
            {
                case 0x01: // Names
                    return Interop.GssApi.GetSourceName(context.GssContext);
                case 0x0C: // NegotiationInfo
                    NegotiationInfoClass negotiationInfoClass = new NegotiationInfoClass(context, Int32.MaxValue);
                    negotiationInfoClass.AuthenticationPackage = NegotiationInfoClass.Kerberos;
                    return negotiationInfoClass;
                case 0: // Sizes
                    // Used only in the Encrypt/Decrypt logic
                case 0x1B: // ClientSpecifiedSpn
                    // Required only in NTLM case with ExtendedProtection
                default:
                    errorCode = SecurityStatus.Unsupported;
                    return null;
            }
        }

        private static SecurityStatus EstablishSecurityContext(
            SafeFreeGssCredentials credential,
            ref SafeDeleteGssContext context,
            string targetName,
            uint inFlags,
            SecurityBuffer inputBuffer,
            SecurityBuffer outputBuffer,
            ref uint outFlags)
        {
            if (context == null)
            {
                context = new SafeDeleteGssContext(targetName, inFlags);
            }

            try
            {
                Interop.libgssapi.SafeGssContextHandle gssContext = context.GssContext;
                bool done = Interop.GssApi.EstablishSecurityContext(
                                  ref gssContext,
                                  credential,
                                  context.TargetName,
                                  inFlags,
                                  inputBuffer.token,
                                  out outputBuffer.token,
                                  out outFlags);

                Debug.Assert(outputBuffer.token != null, "Unexpected null buffer returned by GssApi");
                outputBuffer.size = outputBuffer.token.Length;
                outputBuffer.offset = 0;

                // Save the inner context handle for further calls to libgssapi
                if (context.IsInvalid)
                {
                    context.SetHandle(credential, gssContext);
                }
                return done ? SecurityStatus.OK : SecurityStatus.ContinueNeeded;
            }
            catch (Exception)
            {
                return SecurityStatus.InternalError;
            }
        }
    }   
}