// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Principal;
using System.Runtime.InteropServices;
using ValidationHelper = System.Net.Logging;

namespace System.Net
{
    internal static class NegotiateStreamPal
    {
        private const int LogonDeniedHResult = unchecked((int)0x8009030C);

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
                HResult = unchecked((int)0x80090020);
            }
        }

        private class GenericIdentity : IIdentity
        {
            private readonly string _name;
            private readonly string _authType;

            public string Name
            {
                get { return _name;  }
            }

            public string AuthenticationType
            {
                get { return _authType; }
            }

            public bool IsAuthenticated
            {
                get { return true; }
            }

            internal GenericIdentity(string name, string protocol)
            {
                _name = name;
                _authType = protocol;
            }
        }

        public static bool OSSupportsExtendedProtection
        {
            get { return false; }
        }

        public static void ValidateImpersonationLevel(TokenImpersonationLevel impersonationLevel)
        {

            if (impersonationLevel != TokenImpersonationLevel.Identification)
            {
                throw new ArgumentOutOfRangeException("impersonationLevel", impersonationLevel.ToString(), SR.net_auth_supported_impl_levels);
            }
        }

        public static int GetMaxTokenSize(string package)
        {
            // Token size is only used for output buffer allocations. On non-Windows
            // this is always done by the library
            return 0;
        }

        public static SafeFreeCredentials AcquireDefaultCredential(string moduleName, bool isServer)
        {
            return AcquireCredentialsHandle(moduleName, isServer, string.Empty, string.Empty, string.Empty);
        }

        public static SafeFreeCredentials AcquireCredentialsHandle(string moduleName, bool isServer, string username, string password, string domain)
        {
            if (isServer || string.IsNullOrEmpty(username))
            {
                // In server case, only the keytab file (eg. /etc/krb5.keytab) is used
                // In client case, equivalent of default credentials is to use previous,
                // unexpired Kerberos TGT to get service-specific ticket.
                return new SafeFreeGssCredentials(string.Empty, string.Empty, string.Empty);
            }

            try
            {
                if (!string.Equals(moduleName, NegotiationInfoClass.NTLM, StringComparison.OrdinalIgnoreCase))
                {
                    return new SafeFreeGssCredentials(username, password, domain);
                }
            }
            catch
            {
                // Fallback to NTLM
            }
            return new SafeFreeNtlmCredentials(username, password, domain);
        }

        public static IIdentity GetPeerIdentity(NTAuthentication context, string name, string protocol)
        {
            if (context.IsServer)
            {
                Debug.Assert(
                    string.Equals(protocol, NegotiationInfoClass.Kerberos, StringComparison.OrdinalIgnoreCase),
                    "Unsupported protocol: " + protocol);

                SafeDeleteGssContext securityContext = context.GetValidCompletedContext() as SafeDeleteGssContext;
                if (securityContext == null)
                {
                    throw NNSProtocolException.Instance;
                }
            }

            return new GenericIdentity(name, protocol);
        }

        public static void ThrowCredentialException(long error)
        {
            // HResult corr. to LogonDenied
            if ((int)error == LogonDeniedHResult)
                throw new InvalidCredentialException(SR.net_auth_bad_client_creds);

            if ((int)error == NegoState.ERROR_TRUST_FAILURE)
                throw new AuthenticationException(SR.net_auth_context_expectation_remote);
        }

        public static Exception CreateExceptionFromError(SecurityStatusPal statusCode)
        {
            return NNSProtocolException.Instance;
        }

        public static bool IsLogonDeniedException(Exception e)
        {
            // This method checks for the status code returned by InitializeSecurityContext
            // On non-Windows, this will never corr. to a valid HResult
            return false;
        }

        public static SecurityStatusPal InitializeSecurityContext(SafeFreeCredentials credential,
            ref SafeDeleteContext securityContext, string targetName, ContextFlags inFlags,
            SecurityBuffer[] inputBuffers, SecurityBuffer outputBuffer,
            ref ContextFlags outFlags)
        {
            Debug.Assert((inputBuffers == null) || (inputBuffers.Length < 2), "Channel binding is not yet supported");
            SecurityBuffer inputBuffer = (inputBuffers != null ) && (inputBuffers.Length == 1) ? inputBuffers[0] : null;

            if (credential is SafeFreeNtlmCredentials)
            {
                return InitializeNtlmSecurityContext((SafeFreeNtlmCredentials)credential, ref securityContext, inFlags,
                    inputBuffer, outputBuffer, ref outFlags);
            }
            else
            {
                return EstablishGssSecurityContext((SafeFreeGssCredentials)credential, ref securityContext, targetName, inFlags,
                    inputBuffer, outputBuffer, ref outFlags);
            }
        }

        public static SecurityStatusPal AcceptSecurityContext(SafeFreeCredentials credential,
            ref SafeDeleteContext securityContext, ContextFlags inFlags,
            SecurityBuffer[] inputBuffers, SecurityBuffer outputBuffer,
            ref ContextFlags outFlags)
        {
            SafeFreeGssCredentials gssCredential = credential as SafeFreeGssCredentials;
            Debug.Assert(gssCredential != null, "AcceptSecurityContext is supported only for GSSAPI");
            Debug.Assert(inputBuffers.Length < 2, "Channel binding is not yet supported");

            SecurityBuffer inputBuffer = (inputBuffers.Length == 1) ? inputBuffers[0] : null;
            return EstablishGssSecurityContext(gssCredential, ref securityContext, null, inFlags,
                inputBuffer, outputBuffer, ref outFlags);
        }

        public static SecurityStatusPal CompleteAuthToken(ref SafeDeleteContext securityContext,
            SecurityBuffer[] inputBuffers)
        {
            Debug.Fail("CompleteAuthToken is not required on non-Windows");
            throw new InvalidOperationException("CompleteAuthToken is not required on non-Windows");
        }

        public static int Encrypt(SafeDeleteContext securityContext, object secSizes, bool isConfidential, bool isNTLM, byte[] buffer, int offset, int count, ref byte[] output, uint sequenceNumber)
        {
            if (isNTLM)
            {
                SafeDeleteNtlmContext context = securityContext as SafeDeleteNtlmContext;
                byte[] signature = context.MakeSignature(true, buffer, offset, count);
                if (isConfidential)
                {
                    byte[] cipher = context.EncryptOrDecrypt(true, buffer, offset, count);
                    output = new byte[cipher.Length + signature.Length + 4];
                    Array.Copy(signature, 0, output, 4, signature.Length);
                    Array.Copy(cipher, 0, output, signature.Length + 4, cipher.Length);
                }
                else
                {
                    output = new byte[count + signature.Length + 4];
                    Array.Copy(signature, 0, output, 4, signature.Length);
                    Array.Copy(buffer, offset, output, signature.Length + 4, count);
                }
            }
            else
            {
                SafeDeleteGssContext context = securityContext as SafeDeleteGssContext;
                SafeGssBufferHandle gssBuffer = Interop.GssApi.Encrypt(context.GssContext, isConfidential, buffer, offset, count);
                using (gssBuffer)
                {
                    output = new byte[gssBuffer.Length + 4];
                    if (buffer.Length > 0)
                    {
                        Marshal.Copy(gssBuffer.Value, output, 4, gssBuffer.Length);
                    }
                }
            }
            return output.Length - 4;
        }

        public static int Decrypt(SafeDeleteContext securityContext, bool isConfidential, bool isNTLM, byte[] payload, int offset, int count, out int newOffset, uint expectedSeqNumber)
        {
            if (offset < 0 || offset > (payload == null ? 0 : payload.Length))
            {
                GlobalLog.Assert(false, "NTAuthentication#" + ValidationHelper.HashString(securityContext) + "::Decrypt", "Argument 'offset' out of range.");
                throw new ArgumentOutOfRangeException("offset");
            }
            if (count < 0 || count > (payload == null ? 0 : payload.Length - offset))
            {
                GlobalLog.Assert(false, "NTAuthentication#" + ValidationHelper.HashString(securityContext) + "::Decrypt", "Argument 'count' out of range.");
                throw new ArgumentOutOfRangeException("count");
            }

            newOffset = isNTLM ? (offset + 16) : offset;    // Account for NTLM signature
            if (!isConfidential)
            {
                return VerifySignature(securityContext, payload, offset, count);
            }
            if (isNTLM)
            {
                SafeDeleteNtlmContext context = securityContext as SafeDeleteNtlmContext;
                byte[] message = context.EncryptOrDecrypt(false, payload, newOffset, (count - 16));
                Array.Copy(message, 0, payload, newOffset, message.Length);
                return VerifySignature(securityContext, payload, offset, count);
            }
            else
            {
                return Interop.GssApi.Decrypt(((SafeDeleteGssContext)securityContext).GssContext, payload, offset, count);
            }
        }

        public static int VerifySignature(SafeDeleteContext securityContext, byte[] buffer, int offset, int count)
        {
            if (securityContext is SafeDeleteGssContext)
            {
                return Interop.GssApi.Decrypt(((SafeDeleteGssContext)securityContext).GssContext, buffer, offset, count);
            }
            count -= 16;
            byte[] signature = ((SafeDeleteNtlmContext)securityContext).MakeSignature(false, buffer, offset+16, count);
            for (int i = 0; i < signature.Length; i++)
            {
                if (buffer[offset + i] != signature[i])
                {
                    throw new Exception("Invalid signature");
                }
            }
            return count;
        }

        public static int MakeSignature(SafeDeleteContext securityContext, object secSizes, byte[] buffer, int offset, int count, ref byte[] output)
        {
            if (securityContext is SafeDeleteGssContext)
            {
                SafeDeleteGssContext context = ((SafeDeleteGssContext)securityContext);
                SafeGssBufferHandle gssBuffer = Interop.GssApi.Encrypt(context.GssContext, false, buffer, offset, count);
                using (gssBuffer)
                {
                    output = new byte[gssBuffer.Length];
                    if (gssBuffer.Length > 0)
                    {
                        Marshal.Copy(gssBuffer.Value, output, 0, gssBuffer.Length);
                    }
                }
                return output.Length;
            }
            byte[] signature = ((SafeDeleteNtlmContext)securityContext).MakeSignature(true, buffer, offset, count);
            output = new byte[signature.Length + count];
            Array.Copy(signature, 0, output, 0, signature.Length);
            Array.Copy(buffer, offset, output, signature.Length, count);
            return output.Length;
        }

        public static object QueryContextSecuritySizes(SafeDeleteContext securityContext)
        {
            // The return value is not used for non-Windows
            return null;
        }

        public static string QueryContextClientSpecifiedSpn(SafeDeleteContext securityContext)
        {
            Debug.Fail("QueryContextClientSpecifiedSpn is not required on non-Windows");
            throw new InvalidOperationException("QueryContextClientSpecifiedSpn is not required on non-Windows");
        }

        public static string QueryContextClientSpecifiedSpn(SafeDeleteContext securityContext, out SecurityStatusPal errorCode)
        {
            // Used only to check if OS supports Extended Protection
            errorCode = SecurityStatusPal.Unsupported;
            return string.Empty;
        }

        public static string QueryContextAssociatedName(SafeDeleteContext securityContext)
        {
            SafeDeleteGssContext context = securityContext as SafeDeleteGssContext;
            Debug.Assert(context != null, "NTLM server is not supported");
            return Interop.GssApi.GetSourceName(context.GssContext);
        }

        public static NegotiationInfoClass QueryContextNegotiationInfo(SafeDeleteContext securityContext)
        {
            return new NegotiationInfoClass(securityContext is SafeDeleteNtlmContext);
        }

        private static SecurityStatusPal InitializeNtlmSecurityContext(
            SafeFreeNtlmCredentials credential,
            ref SafeDeleteContext context,
            ContextFlags inFlags,
            SecurityBuffer inputBuffer,
            SecurityBuffer outputBuffer,
            ref ContextFlags outFlags)
        {
            SecurityStatusPal retVal;
            Interop.libheimntlm.NtlmFlags flags;

            try
            {
                if (null == context)
                {
                    flags = GetInteropNtlmFromContextFlagsPal(inFlags);
                    context = new SafeDeleteNtlmContext(credential, flags);
                    outputBuffer.token = Interop.HeimdalNtlm.CreateNegotiateMessage((uint)flags);
                    retVal = SecurityStatusPal.ContinueNeeded;
                }
                else
                {
                    flags = ((SafeDeleteNtlmContext)context).Flags;
                    SafeNtlmBufferHandle sessionKey;
                    outputBuffer.token = Interop.HeimdalNtlm.CreateAuthenticateMessage((uint)flags, credential.UserName,
                        credential.Password, credential.Domain, inputBuffer.token, inputBuffer.offset, inputBuffer.size, out sessionKey);
                    using (sessionKey)
                    {
                        ((SafeDeleteNtlmContext)context).SetKeys(sessionKey);
                    }
                    retVal = SecurityStatusPal.OK;
                }
            }
            catch (System.Exception)
            {
                return SecurityStatusPal.InternalError;
            }
            outFlags = GetContextFlagsPalFromInteropNtlm(flags);
            outputBuffer.size = outputBuffer.token.Length;
            return retVal;
        }

        private static SecurityStatusPal EstablishGssSecurityContext(
            SafeFreeGssCredentials credential,
            ref SafeDeleteContext context,
            string targetName,
            ContextFlags inFlags,
            SecurityBuffer inputBuffer,
            SecurityBuffer outputBuffer,
            ref ContextFlags outFlags)
        {
            uint flags = (uint)GetInteropGssFromContextFlagsPal(inFlags);
            uint outputFlags;

            if (context == null)
            {
                context = new SafeDeleteGssContext(credential, targetName);
            }

            SafeDeleteGssContext gssContext = (SafeDeleteGssContext)context;
            try
            {
                SafeGssContextHandle contextHandle = gssContext.GssContext;
                bool done = Interop.GssApi.EstablishSecurityContext(
                                  ref contextHandle,
                                  credential.GssCredential,
                                  gssContext.TargetName,
                                  flags,
                                  (inputBuffer != null) ? inputBuffer.token : null,
                                  out outputBuffer.token,
                                  out outputFlags);
                Debug.Assert(outputBuffer.token != null, "Unexpected null buffer returned by GssApi");
                outputBuffer.size = outputBuffer.token.Length;
                outputBuffer.offset = 0;

                // Save the inner context handle for further calls to libgssapi
                if (gssContext.GssContext == null)
                {
                    gssContext.SetHandle(contextHandle);
                }
                outFlags = GetContextFlagsPalFromInteropGss((Interop.libgssapi.GssFlags)outputFlags);
                if (done && (gssContext.TargetName != null))
                {
                    // In client case, non-null will cause an extra empty message to be sent
                    Debug.Assert(outputBuffer.token.Length == 0,
                        "Unexpected outgoing token after completed gss_init_sec_context");
                    outputBuffer.token = null;
                }
                return done ? SecurityStatusPal.OK : SecurityStatusPal.ContinueNeeded;
            }
            catch (Exception)
            {
                return SecurityStatusPal.InternalError;
            }
        }

        private static ContextFlags GetContextFlagsPalFromInteropGss(Interop.libgssapi.GssFlags gssFlags)
        {
            ContextFlags flags = ContextFlags.Zero;
            if ((gssFlags & Interop.libgssapi.GssFlags.GSS_C_INTEG_FLAG) != 0)
            {
                flags |= (ContextFlags.AcceptIntegrity | ContextFlags.InitIntegrity);
            }
            if ((gssFlags & Interop.libgssapi.GssFlags.GSS_C_CONF_FLAG) != 0)
            {
                flags |= ContextFlags.Confidentiality;
            }
            if ((gssFlags & Interop.libgssapi.GssFlags.GSS_C_IDENTIFY_FLAG) != 0)
            {
                flags |= ContextFlags.InitIdentify;
            }
            if ((gssFlags & Interop.libgssapi.GssFlags.GSS_C_MUTUAL_FLAG) != 0)
            {
                flags |= ContextFlags.MutualAuth;
            }
            if ((gssFlags & Interop.libgssapi.GssFlags.GSS_C_REPLAY_FLAG) != 0)
            {
                flags |= ContextFlags.ReplayDetect;
            }
            if ((gssFlags & Interop.libgssapi.GssFlags.GSS_C_SEQUENCE_FLAG) != 0)
            {
                flags |= ContextFlags.SequenceDetect;
            }
            return flags;
        }

        private static Interop.libgssapi.GssFlags GetInteropGssFromContextFlagsPal(ContextFlags flags)
        {
            Interop.libgssapi.GssFlags gssFlags = (Interop.libgssapi.GssFlags)0;
            if ((flags & ContextFlags.AcceptIntegrity) != 0)
            {
                gssFlags |= Interop.libgssapi.GssFlags.GSS_C_INTEG_FLAG;
            }
            if ((flags & ContextFlags.Confidentiality) != 0)
            {
                gssFlags |= Interop.libgssapi.GssFlags.GSS_C_CONF_FLAG;
            }
            if ((flags & ContextFlags.InitIdentify) != 0)
            {
                gssFlags |= Interop.libgssapi.GssFlags.GSS_C_IDENTIFY_FLAG;
            }
            if ((flags & ContextFlags.InitIntegrity) != 0)
            {
                gssFlags |= Interop.libgssapi.GssFlags.GSS_C_INTEG_FLAG;
            }
            if ((flags & ContextFlags.MutualAuth) != 0)
            {
                gssFlags |= Interop.libgssapi.GssFlags.GSS_C_MUTUAL_FLAG;
            }
            if ((flags & ContextFlags.ReplayDetect) != 0)
            {
                gssFlags |= Interop.libgssapi.GssFlags.GSS_C_REPLAY_FLAG;
            }
            if ((flags & ContextFlags.SequenceDetect) != 0)
            {
                gssFlags |= Interop.libgssapi.GssFlags.GSS_C_SEQUENCE_FLAG;
            }
            return gssFlags;
        }

        private static ContextFlags GetContextFlagsPalFromInteropNtlm(Interop.libheimntlm.NtlmFlags ntlmFlags)
        {
            ContextFlags flags = ContextFlags.Zero;
            if ((ntlmFlags & Interop.libheimntlm.NtlmFlags.NTLMSSP_NEGOTIATE_SEAL) != 0)
            {
                flags |= ContextFlags.Confidentiality;
            }
            if ((ntlmFlags & Interop.libheimntlm.NtlmFlags.NTLMSSP_NEGOTIATE_SIGN) != 0)
            {
                flags |= ContextFlags.InitIntegrity;    // No NTLM server support
                flags |= ContextFlags.ReplayDetect | ContextFlags.SequenceDetect;
            }
            return flags;
        }

        private static Interop.libheimntlm.NtlmFlags GetInteropNtlmFromContextFlagsPal(ContextFlags flags)
        {
            Interop.libheimntlm.NtlmFlags ntlmFlags = Interop.libheimntlm.NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE | Interop.libheimntlm.NtlmFlags.NTLMSSP_REQUEST_TARGET;
            if ((flags & (ContextFlags.AcceptIntegrity | ContextFlags.InitIntegrity | ContextFlags.Confidentiality)) != 0)
            {
                ntlmFlags |= Interop.libheimntlm.NtlmFlags.NTLMSSP_NEGOTIATE_SIGN | Interop.libheimntlm.NtlmFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | Interop.libheimntlm.NtlmFlags.NTLMSSP_NEGOTIATE_NTLM | Interop.libheimntlm.NtlmFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | Interop.libheimntlm.NtlmFlags.NTLMSSP_NEGOTIATE_128 | Interop.libheimntlm.NtlmFlags.NTLMSSP_NEGOTIATE_KEY_EXCH; 
            }
            if ((flags & ContextFlags.Confidentiality) != 0)
            {
                ntlmFlags |= Interop.libheimntlm.NtlmFlags.NTLMSSP_NEGOTIATE_SEAL;
            }
            return ntlmFlags;
        }
    }
}
