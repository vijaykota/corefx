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
        private const int LogonDenied = unchecked((int) 0x8009030C);
        private const int NtlmSignatureLength = 16; // Input bytes are preceded by a signature

        private class NNSProtocolException : Exception
        {
            internal static readonly Exception Instance;

            // MS-NNS Protocol requires a Windows error code to be  
            // passed back. Hence, we always use NTE_FAIL  
            private const int NTE_FAIL = unchecked((int) 0x80090020);

            static NNSProtocolException()
            {
                Instance = new NNSProtocolException();
            }

            private NNSProtocolException() : base()
            {
                HResult = NTE_FAIL;
            }
        }


        internal IIdentity GetIdentity()
        {
            Debug.Assert(!_context.IsServer, "GetIdentity: Server is not supported");

            string name = _context.Spn;
            string protocol  = _context.ProtocolName;

            return new GenericIdentity(name, protocol);

        }

        internal static string QueryContextAssociatedName(SafeDeleteContext securityContext)
        {
            throw new PlatformNotSupportedException();

        }

        internal static string QueryContextAuthenticationPackage(SafeDeleteContext securityContext)
        {
            SafeDeleteNegoContext negoContext = (SafeDeleteNegoContext)securityContext;
            return negoContext.IsNTLM ? NegotiationInfoClass.NTLM : NegotiationInfoClass.Kerberos;
        }

        internal static object QueryContextSizes(SafeDeleteContext securityContext)
        {
            // This return value is never used
            return null;
        }

        internal static int QueryMaxTokenSize(string package)
        {
            // The value is unused in non-Windows code paths
            return 0;
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
            Debug.Assert(!isServer, "AcquireCredentialsHandle: Server is not yet supported");
            bool ntlmOnly = string.Equals(package, NegotiationInfoClass.NTLM, StringComparison.OrdinalIgnoreCase);
            if (ntlmOnly && (string.IsNullOrWhiteSpace(credential.UserName) || string.IsNullOrWhiteSpace(credential.Password)))
            {
                // NTLM authentication is not possible with default credentials which are no-op
                throw new PlatformNotSupportedException();
            }

            SafeFreeCredentials outCredential;
            if (string.IsNullOrWhiteSpace(credential.UserName) || string.IsNullOrWhiteSpace(credential.Password))
            {
                // In client case, equivalent of default credentials is to use previous,
                // unexpired Kerberos TGT to get service-specific ticket.
                outCredential = new SafeFreeNegoCredentials(false, string.Empty, string.Empty, string.Empty);
            }
            else
            {
                outCredential = new SafeFreeNegoCredentials(ntlmOnly, credential.UserName, credential.Password, credential.Domain);
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
            if ((null != inSecurityBufferArray) && (inSecurityBufferArray.Length > 1))
            {
                throw new PlatformNotSupportedException("No support for channel binding on non-Windows");
            }

            return EstablishSecurityContext(
                (SafeFreeNegoCredentials) credentialsHandle,
                ref securityContext,
                spn,
                requestedContextFlags,
                ((inSecurityBufferArray != null) ? inSecurityBufferArray[0] : null),
                outSecurityBuffer,
                ref contextFlags);
        }

        internal static SecurityStatusPal CompleteAuthToken(
            ref SafeDeleteContext securityContext,
            SecurityBuffer[] inSecurityBufferArray)
        {
            Debug.Assert(inSecurityBufferArray[0].size == 0, "Unexpected output token in last leg of InitSecContext");
            return SecurityStatusPal.OK;
        }

        internal static SecurityStatusPal AcceptSecurityContext(
            SafeFreeCredentials credentialsHandle,
            ref SafeDeleteContext securityContext,
            ContextFlagsPal requestedContextFlags,
            SecurityBuffer[] inSecurityBufferArray,
            SecurityBuffer outSecurityBuffer,
            ref ContextFlagsPal contextFlags)
        {
            throw new PlatformNotSupportedException();
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
            string message = SR.net_auth_alert;
            if ((int)error == LogonDenied)
            {
                message = SR.net_auth_bad_client_creds;
            }

            if ((int)error == NegoState.ERROR_TRUST_FAILURE)
            {
                message = SR.net_auth_context_expectation_remote;
            }

            throw new AuthenticationException(message, null);
        }

        private static bool IsLogonDeniedException(Exception exception)
        {
            return exception.HResult == LogonDenied;
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
            const int prefixLength = sizeof(uint); // Output bytes are preceded by length
            SafeDeleteNegoContext negoContext = securityContext as SafeDeleteNegoContext;
            Debug.Assert((isNtlm == negoContext.IsNTLM), "Inconsistent NTLM parameter");
            if (null != negoContext.GssContext)
            {
                byte[] tempOutput;
                Interop.NetSecurity.Encrypt(negoContext.GssContext, isConfidential, buffer, offset, count, out tempOutput);

                output = new byte[tempOutput.Length + prefixLength];
                Array.Copy(tempOutput, 0, output, prefixLength, tempOutput.Length);
                return tempOutput.Length;
            }
            else
            {
                byte[] signature = negoContext.MakeSignature(true, buffer, offset, count);
                if (isConfidential)
                {
                    byte[] cipher = negoContext.EncryptOrDecrypt(true, buffer, offset, count);
                    output = new byte[cipher.Length + signature.Length + prefixLength];
                    Array.Copy(signature, 0, output, prefixLength, signature.Length);
                    Array.Copy(cipher, 0, output, signature.Length + prefixLength, cipher.Length);
                }
                else
                {
                    output = new byte[count + signature.Length + prefixLength];
                    Array.Copy(signature, 0, output, prefixLength, signature.Length);
                    Array.Copy(buffer, offset, output, signature.Length + prefixLength, count);
                }
                return output.Length;
            }
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
            SafeDeleteNegoContext negoContext = (SafeDeleteNegoContext)securityContext;
            Debug.Assert((isNtlm == negoContext.IsNTLM), "Inconsistent NTLM parameter");

            newOffset = isNtlm ? (offset + NtlmSignatureLength) : offset;    // Account for NTLM signature
            if (!isConfidential)
            {
                return VerifySignature(negoContext, buffer, offset, count);
            }

            if (null != negoContext.GssContext)
            {
                return Interop.NetSecurity.Decrypt(negoContext.GssContext, buffer, offset, count);
            }
            else
            {
                int tempOffset;
                return DecryptNtlm(negoContext, buffer, offset, count, isConfidential, out tempOffset, sequenceNumber);
            }
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
            SafeDeleteNegoContext negoContext = (SafeDeleteNegoContext)securityContext;
            newOffset = offset + NtlmSignatureLength;    // Account for NTLM signature
            byte[] message = negoContext.EncryptOrDecrypt(false, buffer, newOffset, (count - NtlmSignatureLength));
            Array.Copy(message, 0, buffer, newOffset, message.Length);
            return VerifySignature(negoContext, buffer, offset, count);
        }

        private static int VerifySignature(SafeDeleteNegoContext negoContext, byte[] buffer, int offset, int count)
        {
            if (null != negoContext.GssContext)
            {
                return Interop.NetSecurity.Decrypt(negoContext.GssContext, buffer, offset, count);
            }
            count -= NtlmSignatureLength;
            byte[] signature = negoContext.MakeSignature(false, buffer, offset + NtlmSignatureLength, count);
            for (int i = 0; i < signature.Length; i++)
            {
                if (buffer[offset + i] != signature[i])
                {
                    throw new Exception("Invalid signature");
                }
            }
            return count;
        }

        private static SecurityStatusPal EstablishSecurityContext(
          SafeFreeNegoCredentials credential,
          ref SafeDeleteContext context,
          string targetName,
          ContextFlagsPal inFlags,
          SecurityBuffer inputBuffer,
          SecurityBuffer outputBuffer,
          ref ContextFlagsPal outFlags)
        {
            bool isNtlm;
            SafeDeleteNegoContext negoContext;
            SafeGssContextHandle contextHandle = null;

            if (context == null)
            {
                isNtlm = credential.IsNTLM || string.IsNullOrWhiteSpace(targetName);
                negoContext = isNtlm ? null : new SafeDeleteNegoContext(credential, targetName);
                context = negoContext;
            }
            else
            {
                negoContext = (SafeDeleteNegoContext)context;
                isNtlm = negoContext.IsNTLM;
                contextHandle = negoContext.GssContext;
            }

            try
            {
                uint outputFlags;
                bool done = false;

                if (!isNtlm)
                {
                    Interop.NetSecurity.GssFlags inputFlags = GetInteropGssFromContextFlagsPal(inFlags);
                    try
                    {
                        Console.WriteLine("**** vijayko ISC PARAMS:\n cred: {0} target: {1} flags: {2}",
                            credential.GssCredential.DangerousGetHandle().ToString("x8"),
                            negoContext.TargetName.DangerousGetHandle().ToString("x8"), inputFlags);
                        if (null != contextHandle)Console.WriteLine("**** ISC contexthandle: {0}", contextHandle.DangerousGetHandle().ToString("x8"));
                        done = Interop.NetSecurity.EstablishSecurityContext(
                                          ref contextHandle,
                                          credential.GssCredential,
                                          false,
                                          negoContext.TargetName,
                                          inputFlags,
                                          ((inputBuffer != null) ? inputBuffer.token : null),
                                          out outputBuffer.token,
                                          out outputFlags);

                        outFlags = GetContextFlagsPalFromInteropGss((Interop.NetSecurity.GssFlags)outputFlags);

                        // Save the inner context handle for further calls to NetSecurity
                        if (null == negoContext.GssContext)
                        {
                            Console.WriteLine("**** ISC contexthandle: {0}", contextHandle.DangerousGetHandle().ToString("x8"));
                            negoContext.SetGssContext(contextHandle, false);
                        }
                    }
                    catch (Exception ex)
                    {
                        // If this is the first attempt at context creation with non-default
                        // credentials, we need to try NTLM authentication
                        if ((null != contextHandle) || credential.IsDefault)
                        {
                            throw;
                        }
                        Console.WriteLine("***** vijayko INIT_SEC FALL BACK: \n {0} ****", ex);
                        isNtlm = true;
                        negoContext.Dispose();
                        context = null;
                    }
                }

                if (isNtlm)
                {
                    done = EstablishNtlmSecurityContext(
                                      credential,
                                      ref context,
                                      targetName,
                                      inFlags,
                                      inputBuffer,
                                      outputBuffer,
                                      ref outFlags);
                }

                Debug.Assert(outputBuffer.token != null, "Unexpected null buffer returned by GssApi");
                outputBuffer.size = outputBuffer.token.Length;
                outputBuffer.offset = 0;

                return done ? 
                    (isNtlm ? SecurityStatusPal.OK : SecurityStatusPal.CompleteNeeded)
                    : SecurityStatusPal.ContinueNeeded;
            }
            catch(Exception e)
            {
                throw new Exception("***** vijayko BIG EXX: " + e);
                //return SecurityStatusPal.InternalError;
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
