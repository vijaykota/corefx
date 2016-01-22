// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Security;
using System.Security.Principal;
using System.Threading;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using Microsoft.Win32.SafeHandles;

namespace System.Net.Security
{
    //
    // The class maintains the state of the authentication process and the security context.
    // It encapsulates security context and does the real work in authentication and
    // user data encryption with NEGO SSPI package.
    //
    // This is part of the NegotiateStream PAL.
    //
    internal partial class NegoState
    {
        internal IIdentity GetIdentity()
        {
            throw new PlatformNotSupportedException();
        }

        internal static string QueryContextAssociatedName(SafeDeleteContext securityContext)
        {
            return Interop.GssApi.GetSourceName(securityContext.GssContext);

        }

        internal static string QueryContextAuthenticationPackage(SafeDeleteContext securityContext)
        {
            NegotiationInfoClass negotiationInfoClass = new NegotiationInfoClass(securityContext, Int32.MaxValue);
           return negotiationInfoClass.AuthenticationPackage;

        }

        internal static object QueryContextSizes(SafeDeleteContext securityContext)
        {
            throw new PlatformNotSupportedException();
        }

        internal static int QueryMaxTokenSize(string package)
        {
            throw new PlatformNotSupportedException();
        }

        internal static string QueryContextClientSpecifiedSpn(SafeDeleteContext securityContext)
        {
            throw new PlatformNotSupportedException();
        }

        internal static SafeFreeCredentials AcquireDefaultCredential(string package, bool isServer)
        {
            SafeFreeCredentials outCredential;
            AcquireCredentialsHandle(package, isServer, string.Empty, string.Empty, string.Empty, out outCredential);
            return outCredential;
        }

        internal static SafeFreeCredentials AcquireCredentialsHandle(string package, bool isServer, NetworkCredential credential)
        {
            SafeFreeCredentials outCredential;
            if (isServer || string.IsNullOrEmpty(credential.UserName))
            {
                // In server case, only the keytab file (eg. /etc/krb5.keytab) is used
                // In client case, equivalent of default credentials is to use previous,
                // unexpired Kerberos TGT to get service-specific ticket.
                outCredential = new SafeFreeGssCredentials(string.Empty, string.Empty, string.Empty);
            }
            else if (string.Equals(package, "NTLM"))
            {
                outCredential = new SafeFreeNtlmCredentials(credential.UserName, credential.Password, credential.Domain);
            }
            else
            {
                outCredential = new SafeFreeGssCredentials(credential.UserName, credential.Password, credential.Domain);
                // TODO (Issue #3717): Fall back to NTLM if Kerberos ticket cannot be obtained
            }
            return outCredential;

        }

        internal static SecurityStatusPal InitializeSecurityContext(
            SafeFreeCredentials credentialsHandle,
            ref SafeDeleteContext securityContext,
            string spn,
            ContextFlagsPal requestedContextFlags,
            SecurityBuffer[] inSecurityBufferArray,
            SecurityBuffer outSecurityBuffer,
            ref ContextFlagsPal contextFlags)
        {
            // TODO (Issue #3718): The second buffer can contain a channel binding which is not yet supported 
            if (inSecurityBufferArray.Length > 1)
            {
                throw new NotImplementedException("No support for channel binding on non-Windows");
            }

            //if (IsNtlmClient(spn, credentialsHandle))
            //{
            //    return InitializeNtlmSecurityContext((SafeFreeNtlmCredentials) credentialsHandle, ref securityContext,
            //        requestedContextFlags, inSecurityBufferArray[0], outSecurityBuffer);
            //}
            return EstablishSecurityContext((SafeFreeGssCredentials) credentialsHandle, ref securityContext, false, spn,
                requestedContextFlags, inSecurityBufferArray[0], outSecurityBuffer, ref contextFlags);

        }

        internal static SecurityStatusPal CompleteAuthToken(
            ref SafeDeleteContext securityContext,
            SecurityBuffer[] inSecurityBufferArray)
        {
            throw new PlatformNotSupportedException();
        }

        internal static SecurityStatusPal AcceptSecurityContext(
            SafeFreeCredentials credentialsHandle,
            ref SafeDeleteContext securityContext,
            ContextFlagsPal requestedContextFlags,
            SecurityBuffer[] inSecurityBufferArray,
            SecurityBuffer outSecurityBuffer,
            ref ContextFlagsPal contextFlags)
        {
            return EstablishSecurityContext((SafeFreeGssCredentials)credentialsHandle, ref securityContext, false, string.Empty, (Interop.NetSecurity.GssFlags)requestedContextFlags, inSecurityBufferArray[0], outSecurityBuffer, ref contextFlags);

        }

        private static void ValidateImpersonationLevel(TokenImpersonationLevel impersonationLevel)
        {
            throw new PlatformNotSupportedException();
        }

        private static void ThrowCredentialException(long error)
        {
            throw new PlatformNotSupportedException();
        }

        private static bool IsLogonDeniedException(Exception exception)
        {
            throw new PlatformNotSupportedException();
        }

        internal static Exception CreateExceptionFromError(SecurityStatusPal statusCode)
        {
            throw new PlatformNotSupportedException();
        }

        internal static int Encrypt(
            SafeDeleteContext securityContext,
            byte[] buffer,
            int offset,
            int count,
            object secSizes,
            bool isConfidential,
            bool isNtlm,
            ref byte[] output,
            uint sequenceNumber)
        {
            //if (securityContext is SafeDeleteGssContext)
            //{
                // Sequence number is not used by libgssapi
                SafeDeleteGssContext gssContext = securityContext as SafeDeleteGssContext;
                return Interop.GssApi.Encrypt(gssContext.GssContext, gssContext.NeedsEncryption, buffer, offset, count, out output);
            //}

            //SafeDeleteNtlmContext context = securityContext as SafeDeleteNtlmContext;
            //byte[] cipher = context.EncryptOrDecrypt(true, buffer, offset, count);
            //byte[] signature = context.MakeSignature(true, buffer, offset, count);
            //output = new byte[cipher.Length + signature.Length];
            //Array.Copy(signature, 0, output, 0, signature.Length);
            //Array.Copy(cipher, 0, output, signature.Length, cipher.Length);
            //return output.Length;

        }

        internal static int Decrypt(
            SafeDeleteContext securityContext,
            byte[] buffer,
            int offset,
            int count,
            bool isConfidential,
            bool isNtlm,
            out int newOffset,
            uint sequenceNumber)
        {
            //if (securityContext is SafeDeleteGssContext)
            //{
                // Sequence number is not used by libgssapi
                newOffset = offset;
                return Interop.GssApi.Decrypt(((SafeDeleteGssContext)securityContext).GssContext, buffer, offset, count);
            //}
            //SafeDeleteNtlmContext context = securityContext as SafeDeleteNtlmContext;
            //byte[] message = context.EncryptOrDecrypt(false, buffer, (offset + 16), (count - 16));
            //Array.Copy(message, 0, buffer, (offset + 16), message.Length);
            //return VerifySignature(securityContext, buffer, offset, count, out newOffset, sequenceNumber);

        }

        internal static int DecryptNtlm(
            SafeDeleteContext securityContext,
            byte[] buffer,
            int offset,
            int count,
            bool isConfidential,
            out int newOffset,
            uint sequenceNumber)
        {
            throw new PlatformNotSupportedException();
        }

        private static SecurityStatusPal EstablishSecurityContext(
          SafeFreeGssCredentials credential,
          ref SafeHandle context,
          bool isNtlm,
          string targetName,
          Interop.NetSecurity.GssFlags inFlags,
          SecurityBuffer inputBuffer,
          SecurityBuffer outputBuffer,
          ref uint outFlags)
        {
            if (context == null)
            {
                context = new SafeDeleteGssContext(targetName, inFlags);
            }

            SafeDeleteGssContext gssContext = (SafeDeleteGssContext)context;
            try
            {
                SafeGssContextHandle contextHandle = gssContext.GssContext;
                bool done = Interop.GssApi.EstablishSecurityContext(
                                  ref contextHandle,
                                  credential.GssCredential,
                                  isNtlm,
                                  gssContext.TargetName,
                                  inFlags,
                                  inputBuffer.token,
                                  out outputBuffer.token,
                                  out outFlags);

                Debug.Assert(outputBuffer.token != null, "Unexpected null buffer returned by GssApi");
                outputBuffer.size = outputBuffer.token.Length;
                outputBuffer.offset = 0;

                // Save the inner context handle for further calls to libgssapi
                if (gssContext.IsInvalid)
                {
                    gssContext.SetHandle(credential, contextHandle);
                }
                return done ? SecurityStatusPal.OK : SecurityStatusPal.ContinueNeeded;
            }
            catch
            {
                return SecurityStatusPal.InternalError;
            }
        }

    }
}
