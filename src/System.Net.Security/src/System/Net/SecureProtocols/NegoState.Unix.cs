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
        private class NNSProtocolException : Exception
        {
            internal static readonly Exception Instance;

            static NNSProtocolException()
            {
                Instance = new NNSProtocolException();
            }

            // MS-NNS Protocol requires a Windows error code to be  
            // passed back. Hence, we always use NTE_FAIL  
            private NNSProtocolException() : base()
            {
                HResult = unchecked((int) 0x80090020);
            }
        }


        internal IIdentity GetIdentity()
        {
            string name = _context.IsServer ? _context.AssociatedName : _context.Spn;
            string protocol  = _context.ProtocolName;

            if (_context.IsServer)
            {
                Debug.Assert(
                    string.Equals(protocol, NegotiationInfoClass.Kerberos, StringComparison.OrdinalIgnoreCase),
                    "Unsupported protocol: " + protocol);

                SecurityStatusPal status;
                SafeDeleteGssContext securityContext = _context.GetContext(out status) as SafeDeleteGssContext;
                if (securityContext == null)
                {
                    throw NNSProtocolException.Instance;
                }
            }

            return new GenericIdentity(name, protocol);

        }

        internal static string QueryContextAssociatedName(SafeDeleteContext securityContext)
        {
            throw new PlatformNotSupportedException();

        }

        internal static string QueryContextAuthenticationPackage(SafeDeleteContext securityContext)
        {
            throw new PlatformNotSupportedException();
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
           return AcquireCredentialsHandle(package, isServer, new NetworkCredential(string.Empty, string.Empty, string.Empty));
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
            //else if (string.Equals(package, "NTLM"))
            //{
            //    outCredential = new SafeFreeNtlmCredentials(credential.UserName, credential.Password, credential.Domain);
            //}
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
            return EstablishSecurityContext((SafeFreeGssCredentials)credentialsHandle, ref securityContext, false, string.Empty, requestedContextFlags, inSecurityBufferArray[0], outSecurityBuffer, ref contextFlags);
        }

        private static void ValidateImpersonationLevel(TokenImpersonationLevel impersonationLevel)
        {
            if (impersonationLevel != TokenImpersonationLevel.Identification)
            {
                throw new ArgumentOutOfRangeException("impersonationLevel", impersonationLevel.ToString(),
                    SR.net_auth_supported_impl_levels);
            }

        }

        private static void ThrowCredentialException(long error)
        {
            // HResult corr. to LogonDenied  
                 //if ((int)error == NegoState)
                 // throw new InvalidCredentialException(SR.net_auth_bad_client_creds);
         
                 //    if ((int)error == NegoState.ERROR_TRUST_FAILURE)
                 // throw new AuthenticationException(SR.net_auth_context_expectation_remote);

        }

        private static bool IsLogonDeniedException(Exception exception)
        {
            throw new PlatformNotSupportedException();
        }

        internal static Exception CreateExceptionFromError(SecurityStatusPal statusCode)
        {
            return NNSProtocolException.Instance;
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
                // Sequence number is not used by NetSecurity
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
                // Sequence number is not used by NetSecurity
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
          ref SafeDeleteContext context,
          bool isNtlm,
          string targetName,
          ContextFlagsPal inFlags,
          SecurityBuffer inputBuffer,
          SecurityBuffer outputBuffer,
          ref ContextFlagsPal outFlags)
        {
            uint outputFlags;
            if (context == null)
            {
                context = new SafeDeleteGssContext(targetName,(uint) inFlags) as SafeDeleteContext;
            }

            SafeDeleteGssContext gssContext = (SafeDeleteGssContext)context;
            try
            {
                SafeGssContextHandle contextHandle = gssContext.GssContext;
                bool done = Interop.GssApi.EstablishSecurityContext(
                                  ref contextHandle,
                                  credential,
                                  isNtlm,
                                  gssContext.TargetName,
                                  GetInteropGssFromContextFlagsPal(inFlags),
                                  inputBuffer.token,
                                  out outputBuffer.token,
                                  out outputFlags);

                Debug.Assert(outputBuffer.token != null, "Unexpected null buffer returned by GssApi");
                outputBuffer.size = outputBuffer.token.Length;
                outputBuffer.offset = 0;

                // Save the inner context handle for further calls to NetSecurity
                outFlags = GetContextFlagsPalFromInteropGss((Interop.NetSecurity.GssFlags)outputFlags);

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
        private static ContextFlagsPal GetContextFlagsPalFromInteropGss(Interop.NetSecurity.GssFlags gssFlags)
        {
            ContextFlagsPal flags = ContextFlagsPal.Zero;
            if ((gssFlags & Interop.NetSecurity.GssFlags.GSS_C_INTEG_FLAG) != 0)
            {
                flags |= (ContextFlagsPal.AcceptIntegrity | ContextFlagsPal.InitIntegrity);
            }
            if ((gssFlags & Interop.NetSecurity.GssFlags.GSS_C_CONF_FLAG) != 0)
            {
                flags |= ContextFlagsPal.Confidentiality;
            }
            if ((gssFlags & Interop.NetSecurity.GssFlags.GSS_C_IDENTIFY_FLAG) != 0)
            {
                flags |= ContextFlagsPal.InitIdentify;
            }
            if ((gssFlags & Interop.NetSecurity.GssFlags.GSS_C_MUTUAL_FLAG) != 0)
            {
                flags |= ContextFlagsPal.MutualAuth;
            }
            if ((gssFlags & Interop.NetSecurity.GssFlags.GSS_C_REPLAY_FLAG) != 0)
            {
                flags |= ContextFlagsPal.ReplayDetect;
            }
            if ((gssFlags & Interop.NetSecurity.GssFlags.GSS_C_SEQUENCE_FLAG) != 0)
            {
                flags |= ContextFlagsPal.SequenceDetect;
            }
            return flags;
        }

        private static Interop.NetSecurity.GssFlags GetInteropGssFromContextFlagsPal(ContextFlagsPal flags)
        {
            Interop.NetSecurity.GssFlags gssFlags = (Interop.NetSecurity.GssFlags)0;
            if ((flags & ContextFlagsPal.AcceptIntegrity) != 0)
            {
                gssFlags |= Interop.NetSecurity.GssFlags.GSS_C_INTEG_FLAG;
            }
            if ((flags & ContextFlagsPal.Confidentiality) != 0)
            {
                gssFlags |= Interop.NetSecurity.GssFlags.GSS_C_CONF_FLAG;
            }
            if ((flags & ContextFlagsPal.InitIdentify) != 0)
            {
                gssFlags |= Interop.NetSecurity.GssFlags.GSS_C_IDENTIFY_FLAG;
            }
            if ((flags & ContextFlagsPal.InitIntegrity) != 0)
            {
                gssFlags |= Interop.NetSecurity.GssFlags.GSS_C_INTEG_FLAG;
            }
            if ((flags & ContextFlagsPal.MutualAuth) != 0)
            {
                gssFlags |= Interop.NetSecurity.GssFlags.GSS_C_MUTUAL_FLAG;
            }
            if ((flags & ContextFlagsPal.ReplayDetect) != 0)
            {
                gssFlags |= Interop.NetSecurity.GssFlags.GSS_C_REPLAY_FLAG;
            }
            if ((flags & ContextFlagsPal.SequenceDetect) != 0)
            {
                gssFlags |= Interop.NetSecurity.GssFlags.GSS_C_SEQUENCE_FLAG;
            }
            return gssFlags;
        }

    }
}
