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
            out SafeHandle outCredential)
        {
            if (isInBoundCred || string.IsNullOrEmpty(username))
            {
                // In server case, only the keytab file (eg. /etc/krb5.keytab) is used
                // In client case, equivalent of default credentials is to use previous,
                // unexpired Kerberos TGT to get service-specific ticket.
                outCredential = new SafeFreeGssCredentials(string.Empty, string.Empty, string.Empty);
            }
            else if (string.Equals(moduleName, "NTLM"))
            {
                outCredential = new SafeFreeNtlmCredentials(username, password, domain);
            }
            else
            {
                outCredential = new SafeFreeGssCredentials(username, password, domain);
                // TODO (Issue #3717): Fall back to NTLM if Kerberos ticket cannot be obtained
            }
            return SecurityStatus.OK;
        }

        public static SecurityStatus AcquireDefaultCredential(string moduleName, bool isInBoundCred, out SafeHandle outCredential)
        {
            return AcquireCredentialsHandle(moduleName, isInBoundCred, string.Empty, string.Empty, string.Empty, out outCredential);
        }

        public static SecurityStatus AcceptSecurityContext(
            SafeHandle credential,
            ref SafeHandle context,
            SecurityBuffer inputBuffer,
            uint inFlags,
            uint endianNess,
            SecurityBuffer outputBuffer,
            ref uint outFlags)
        {
            return EstablishSecurityContext((SafeFreeGssCredentials)credential, ref context, string.Empty, inFlags, inputBuffer, outputBuffer, ref outFlags);
        }

        public static SecurityStatus InitializeSecurityContext(
            SafeHandle credential,
            ref SafeHandle context,
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

            if (IsNtlmClient(targetName, credential))
            {
                return InitializeNtlmSecurityContext((SafeFreeNtlmCredentials)credential, ref context, inFlags, inputBuffers[0], outputBuffer);
            }
            return EstablishSecurityContext((SafeFreeGssCredentials)credential, ref context, targetName, inFlags, inputBuffers[0], outputBuffer, ref outFlags);
        }

        public static int Encrypt(SafeHandle securityContext, byte[] buffer, int offset, int count, ref byte[] output, uint sequenceNumber)
        {
            if (securityContext is SafeDeleteGssContext)
            {
                // Sequence number is not used by libgssapi
                SafeDeleteGssContext gssContext = securityContext as SafeDeleteGssContext;
                return Interop.GssApi.Encrypt(gssContext.GssContext, gssContext.NeedsEncryption, buffer, offset, count, out output);
            }

            // TODO (Issue# 3717): Figure out why sign verification on peer fails
            SafeDeleteNtlmContext context = securityContext as SafeDeleteNtlmContext;
            byte[] cipher = context.EncryptOrDecrypt(true, buffer, offset, count);
            byte[] signature = context.MakeSignature(true, buffer, offset, count);
            output = new byte[cipher.Length + signature.Length];
            Array.Copy(signature, 0, output, 0, signature.Length);
            Array.Copy(cipher, 0, output, signature.Length, cipher.Length);
            return output.Length;
        }

        public static int Decrypt(SafeHandle securityContext, byte[] buffer, int offset, int count, out int newOffset, uint sequenceNumber)
        {
            if (securityContext is SafeDeleteGssContext)
            {
                // Sequence number is not used by libgssapi
                newOffset = offset;
                return Interop.GssApi.Decrypt(((SafeDeleteGssContext)securityContext).GssContext, buffer, offset, count);
            }
            SafeDeleteNtlmContext context = securityContext as SafeDeleteNtlmContext;
            byte[] message = context.EncryptOrDecrypt(false, buffer, (offset + 16), (count - 16));
            Array.Copy(message, 0, buffer, (offset + 16), message.Length);
            return VerifySignature(securityContext, buffer, offset, count, out newOffset, sequenceNumber);
        }

        public static int MakeSignature(SafeHandle securityContext, byte[] buffer, int offset, int count, ref byte[] output, uint sequenceNumber)
        {
            if (securityContext is SafeDeleteGssContext)
            {
                // Sequence number is not used by libgssapi
                SafeDeleteGssContext context = ((SafeDeleteGssContext)securityContext);
                return Interop.GssApi.Encrypt(context.GssContext, context.NeedsEncryption, buffer, offset, count, out output);
            }
            byte[] signature = ((SafeDeleteNtlmContext) securityContext).MakeSignature(true, buffer, offset, count);
            output = new byte[signature.Length + count];
            Array.Copy(signature, 0, output, 0, signature.Length);
            Array.Copy(buffer, offset, output, signature.Length, count);
            return output.Length;
        }

        public static int VerifySignature(SafeHandle securityContext, byte[] buffer, int offset, int count, out int newOffset, uint sequenceNumber)
        {
            if (securityContext is SafeDeleteGssContext)
            {
                // Sequence number is not used by libgssapi
                newOffset = offset;
                return Interop.GssApi.Decrypt(((SafeDeleteGssContext)securityContext).GssContext, buffer, offset, count);
            }
            newOffset = offset + 16;
            count -= 16;
            byte[] signature = ((SafeDeleteNtlmContext) securityContext).MakeSignature(false, buffer, newOffset, count);
            for (int i = 0; i < signature.Length; i++)
            {
                if (buffer[offset + i] != signature[i]) throw new Exception("Invalid signature");
            }
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

        private static bool IsNtlmClient(string targetName, SafeHandle credential)
        {
            return string.IsNullOrEmpty(targetName) || (credential is SafeFreeNtlmCredentials);
        }

        private static SecurityStatus InitializeNtlmSecurityContext(
            SafeFreeNtlmCredentials credential,
            ref SafeHandle context,
            uint inFlags,
            SecurityBuffer inputBuffer,
            SecurityBuffer outputBuffer)
        {
            SecurityStatus retVal;

            if (null == context)
            {
                context = new SafeDeleteNtlmContext(credential, inFlags);
                outputBuffer.token = Interop.HeimdalNtlm.CreateNegotiateMessage(inFlags);
                retVal = SecurityStatus.ContinueNeeded;
            }
            else
            {
                uint flags = ((SafeDeleteNtlmContext)context).Flags;
                Interop.libheimntlm.SafeNtlmBufferHandle sessionKey;
                outputBuffer.token = Interop.HeimdalNtlm.CreateAuthenticateMessage(flags, credential.UserName,
                    credential.Password, credential.Domain, inputBuffer.token, inputBuffer.offset, inputBuffer.size, out sessionKey);
                using (sessionKey)
                {
                    ((SafeDeleteNtlmContext)context).SetKeys(sessionKey);
                }
                retVal = SecurityStatus.OK;
            }
            outputBuffer.size = outputBuffer.token.Length;
            return retVal;
        }

        private static SecurityStatus EstablishSecurityContext(
            SafeFreeGssCredentials credential,
            ref SafeHandle context,
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

            SafeDeleteGssContext gssContext = (SafeDeleteGssContext) context;
            try
            {
                Interop.libgssapi.SafeGssContextHandle contextHandle = gssContext.GssContext;
                bool done = Interop.GssApi.EstablishSecurityContext(
                                  ref contextHandle,
                                  credential,
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
                return done ? SecurityStatus.OK : SecurityStatus.ContinueNeeded;
            }
            catch (Exception)
            {
                return SecurityStatus.InternalError;
            }
        }
    }   
}