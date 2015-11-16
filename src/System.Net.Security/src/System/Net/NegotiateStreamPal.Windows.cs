// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net.Security;
using System.Security;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using ValidationHelper = System.Net.Logging;

namespace System.Net
{
    internal static class NegotiateStreamPal
    {
        // On Windows 7 and above, OS supports this
        public static bool OSSupportsExtendedProtection
        {
            get { return true; }
        }

        public static void ValidateImpersonationLevel(TokenImpersonationLevel impersonationLevel)
        {

            if (impersonationLevel != TokenImpersonationLevel.Identification &&
                impersonationLevel != TokenImpersonationLevel.Impersonation &&
                impersonationLevel != TokenImpersonationLevel.Delegation)
            {
                throw new ArgumentOutOfRangeException("impersonationLevel", impersonationLevel.ToString(), SR.net_auth_supported_impl_levels);
            }
        }

        public static int GetMaxTokenSize(string package)
        {
            return SSPIWrapper.GetVerifyPackageInfo(GlobalSSPI.SSPIAuth, package, true).MaxToken;
        }

        public static SafeFreeCredentials AcquireDefaultCredential(string moduleName, bool isServer)
        {
            Interop.Secur32.CredentialUse usage = isServer
                ? Interop.Secur32.CredentialUse.Inbound
                : Interop.Secur32.CredentialUse.Outbound;

            return SSPIWrapper.AcquireDefaultCredential(GlobalSSPI.SSPIAuth, moduleName, usage);
        }

        public static SafeFreeCredentials AcquireCredentialsHandle(string moduleName, bool isServer, string username, string password, string domain)
        {
            Interop.Secur32.CredentialUse usage = isServer
                ? Interop.Secur32.CredentialUse.Inbound
                : Interop.Secur32.CredentialUse.Outbound;

#if false
            if (!isWin7OrLater)
            {
                Interop.Secur32.AuthIdentity authIdentity = new Interop.Secur32.AuthIdentity(username, password, domain);
                return SSPIWrapper.AcquireCredentialsHandle(GlobalSSPI.SSPIAuth, moduleName, usage, ref authIdentity);
            }
            else
#endif
            {
                SafeSspiAuthDataHandle authData = null;
                try
                {
                    authData = SafeSspiAuthDataHandle.Create(username, password, domain);
                    return SSPIWrapper.AcquireCredentialsHandle(GlobalSSPI.SSPIAuth, moduleName, usage, ref authData);
                }
                finally
                {
                    if (authData != null)
                    {
                        authData.Dispose();
                    }
                }
            }
        }

        public static IIdentity GetPeerIdentity(NTAuthentication context, string name, string protocol)
        {
            IIdentity result = null;
            if (context.IsServer)
            {
                SecurityContextTokenHandle token = null;
                try
                {
                    SafeDeleteContext securityContext = context.GetValidCompletedContext();
                    if (securityContext == null)
                    {
                        throw new Win32Exception((int)SecurityStatusPal.InvalidHandle);
                    }

                    // This will return an client token when conducted authentication on server side'
                    // This token can be used ofr impersanation
                    // We use it to create a WindowsIdentity and hand it out to the server app.
                    Interop.SecurityStatus status = (Interop.SecurityStatus)SSPIWrapper.QuerySecurityContextToken(
                        GlobalSSPI.SSPIAuth,
                        securityContext,
                        out token);
                    if (status != Interop.SecurityStatus.OK)
                    {
                        throw new Win32Exception((int)status);
                    }
#if false
                    result = new WindowsIdentity(token.DangerousGetHandle(), protocol, WindowsAccountType.Normal, true);
#else
                    // TODO: Is this the correct replacement?
                    result = new WindowsIdentity(token.DangerousGetHandle());
#endif
                    return result;
                }
                catch (SecurityException)
                {
                    //ignore and construct generic Identity if failed due to security problem
                }
                finally
                {
                    if (token != null)
                    {
                        token.Dispose();
                    }
                }
            }

            // on the client we don't have access to the remote side identity.
            result = new GenericIdentity(name, protocol);
            return result;
        }

        public static void ThrowCredentialException(long error)
        {
            Win32Exception e = new Win32Exception((int)error);

            if (e.NativeErrorCode == (int) Interop.SecurityStatus.LogonDenied)
                throw new InvalidCredentialException(SR.net_auth_bad_client_creds, e);

            if (e.NativeErrorCode == NegoState.ERROR_TRUST_FAILURE)
                throw new AuthenticationException(SR.net_auth_context_expectation_remote, e);
        }

        public static Exception CreateExceptionFromError(SecurityStatusPal statusCode)
        {
            return new Win32Exception((int)SslStreamPal.GetInteropFromSecurityStatusPal(statusCode));
        }

        public static bool IsLogonDeniedException(Exception e)
        {
            Win32Exception win32exception = e as Win32Exception;

            return (win32exception != null) && (win32exception.NativeErrorCode == (int) Interop.SecurityStatus.LogonDenied);
        }

        public static SecurityStatusPal InitializeSecurityContext(SafeFreeCredentials credential,
            ref SafeDeleteContext securityContext, string targetName, ContextFlags inFlags,
            SecurityBuffer[] inputBuffers, SecurityBuffer outputBuffer,
            ref ContextFlags outFlags)
        {
            Interop.Secur32.ContextFlags inputFlags = GetInteropFromContextFlagsPal(inFlags);
            Interop.Secur32.ContextFlags outputFlags = Interop.Secur32.ContextFlags.Zero;
            int errorCode = SSPIWrapper.InitializeSecurityContext(GlobalSSPI.SSPIAuth, credential,
                ref securityContext, targetName, inputFlags, Interop.Secur32.Endianness.Network, inputBuffers, outputBuffer,
                ref outputFlags);
            SecurityStatusPal status = SslStreamPal.GetSecurityStatusPalFromWin32Int(errorCode);
            if ((status == SecurityStatusPal.OK) || (status == SecurityStatusPal.ContinueNeeded))
            {
                outFlags = GetContextFlagsPalFromInterop(outputFlags);
            }
            return status;
        }

        public static SecurityStatusPal AcceptSecurityContext(SafeFreeCredentials credential,
            ref SafeDeleteContext securityContext, ContextFlags inFlags,
            SecurityBuffer[] inputBuffers, SecurityBuffer outputBuffer,
            ref ContextFlags outFlags)
        {
            Interop.Secur32.ContextFlags inputFlags = GetInteropFromContextFlagsPal(inFlags);
            Interop.Secur32.ContextFlags outputFlags = Interop.Secur32.ContextFlags.Zero;
            int errorCode = SSPIWrapper.AcceptSecurityContext(GlobalSSPI.SSPIAuth, credential,
                ref securityContext, inputFlags, Interop.Secur32.Endianness.Network, inputBuffers, outputBuffer,
                ref outputFlags);
            SecurityStatusPal status = SslStreamPal.GetSecurityStatusPalFromWin32Int(errorCode);
            if ((status == SecurityStatusPal.OK) || (status == SecurityStatusPal.ContinueNeeded))
            {
                outFlags = GetContextFlagsPalFromInterop(outputFlags);
            }
            return status;
        }

        public static SecurityStatusPal CompleteAuthToken(ref SafeDeleteContext securityContext,
            SecurityBuffer[] inputBuffers)
        {
            int errorCode = SSPIWrapper.CompleteAuthToken(GlobalSSPI.SSPIAuth, ref securityContext,
                inputBuffers);
            return SslStreamPal.GetSecurityStatusPalFromWin32Int(errorCode);
        }

        public static int Encrypt(SafeDeleteContext securityContext, object secSizes, bool isConfidential, bool isNTLM, byte[] buffer, int offset, int count, ref byte[] output, uint sequenceNumber)
        {
            SecSizes sizes = secSizes as SecSizes;

            try
            {
                int maxCount = checked(Int32.MaxValue - 4 - sizes.BlockSize - sizes.SecurityTrailer);

                if (count > maxCount || count < 0)
                {
                    throw new ArgumentOutOfRangeException("count", SR.Format(SR.net_io_out_range, maxCount));
                }
            }
            catch (Exception)
            {
                GlobalLog.Assert(false, "NTAuthentication#" + ValidationHelper.HashString(securityContext) + "::Encrypt", "Arguments out of range.");
                throw;
            }

            int resultSize = count + sizes.SecurityTrailer + sizes.BlockSize;
            if (output == null || output.Length < resultSize + 4)
            {
                output = new byte[resultSize + 4];
            }

            // make a copy of user data for in-place encryption
            Buffer.BlockCopy(buffer, offset, output, 4 + sizes.SecurityTrailer, count);

            // prepare buffers TOKEN(signautre), DATA and Padding
            SecurityBuffer[] securityBuffer = new SecurityBuffer[3];
            securityBuffer[0] = new SecurityBuffer(output, 4, sizes.SecurityTrailer, SecurityBufferType.Token);
            securityBuffer[1] = new SecurityBuffer(output, 4 + sizes.SecurityTrailer, count, SecurityBufferType.Data);
            securityBuffer[2] = new SecurityBuffer(output, 4 + sizes.SecurityTrailer + count, sizes.BlockSize, SecurityBufferType.Padding);

            int errorCode;
            if (isConfidential)
            {
                errorCode = SSPIWrapper.EncryptMessage(GlobalSSPI.SSPIAuth, securityContext, securityBuffer, sequenceNumber);
            }
            else
            {
                if (isNTLM)
                    securityBuffer[1].type |= SecurityBufferType.ReadOnlyFlag;
                errorCode = SSPIWrapper.MakeSignature(GlobalSSPI.SSPIAuth, securityContext, securityBuffer, 0);
            }


            if (errorCode != 0)
            {
                GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(securityContext) + "::Encrypt() throw Error = " + errorCode.ToString("x", NumberFormatInfo.InvariantInfo));
                throw new Win32Exception(errorCode);
            }

            // Compacting the result...
            resultSize = securityBuffer[0].size;
            bool forceCopy = false;
            if (resultSize != sizes.SecurityTrailer)
            {
                forceCopy = true;
                Buffer.BlockCopy(output, securityBuffer[1].offset, output, 4 + resultSize, securityBuffer[1].size);
            }

            resultSize += securityBuffer[1].size;
            if (securityBuffer[2].size != 0 && (forceCopy || resultSize != (count + sizes.SecurityTrailer)))
                Buffer.BlockCopy(output, securityBuffer[2].offset, output, 4 + resultSize, securityBuffer[2].size);

            resultSize += securityBuffer[2].size;

            unchecked
            {
                output[0] = (byte)((resultSize) & 0xFF);
                output[1] = (byte)(((resultSize) >> 8) & 0xFF);
                output[2] = (byte)(((resultSize) >> 16) & 0xFF);
                output[3] = (byte)(((resultSize) >> 24) & 0xFF);
            }
            return resultSize + 4;
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

            if (isNTLM)
                return DecryptNtlm(securityContext, isConfidential, payload, offset, count, out newOffset, expectedSeqNumber);

            //
            // Kerberos and up
            //

            SecurityBuffer[] securityBuffer = new SecurityBuffer[2];
            securityBuffer[0] = new SecurityBuffer(payload, offset, count, SecurityBufferType.Stream);
            securityBuffer[1] = new SecurityBuffer(0, SecurityBufferType.Data);

            int errorCode;
            if (isConfidential)
            {
                errorCode = SSPIWrapper.DecryptMessage(GlobalSSPI.SSPIAuth, securityContext, securityBuffer, expectedSeqNumber);
            }
            else
            {
                errorCode = SSPIWrapper.VerifySignature(GlobalSSPI.SSPIAuth, securityContext, securityBuffer, expectedSeqNumber);
            }

            if (errorCode != 0)
            {
                GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(securityContext) + "::Decrypt() throw Error = " + errorCode.ToString("x", NumberFormatInfo.InvariantInfo));
                throw new Win32Exception(errorCode);
            }

            if (securityBuffer[1].type != SecurityBufferType.Data)
                throw new InternalException();

            newOffset = securityBuffer[1].offset;
            return securityBuffer[1].size;
        }

        private static int DecryptNtlm(SafeDeleteContext securityContext, bool isConfidential, byte[] payload, int offset, int count, out int newOffset, uint expectedSeqNumber)
        {
            // For the most part the arguments are verified in Encrypt().
            if (count < 16)
            {
                GlobalLog.Assert(false, "NTAuthentication#" + ValidationHelper.HashString(securityContext) + "::DecryptNtlm", "Argument 'count' out of range.");
                throw new ArgumentOutOfRangeException("count");
            }

            SecurityBuffer[] securityBuffer = new SecurityBuffer[2];
            securityBuffer[0] = new SecurityBuffer(payload, offset, 16, SecurityBufferType.Token);
            securityBuffer[1] = new SecurityBuffer(payload, offset + 16, count - 16, SecurityBufferType.Data);

            int errorCode;
            SecurityBufferType realDataType = SecurityBufferType.Data;

            if (isConfidential)
            {
                errorCode = SSPIWrapper.DecryptMessage(GlobalSSPI.SSPIAuth, securityContext, securityBuffer, expectedSeqNumber);
            }
            else
            {
                realDataType |= SecurityBufferType.ReadOnlyFlag;
                securityBuffer[1].type = realDataType;
                errorCode = SSPIWrapper.VerifySignature(GlobalSSPI.SSPIAuth, securityContext, securityBuffer, expectedSeqNumber);
            }

            if (errorCode != 0)
            {
                GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(securityContext) + "::Decrypt() throw Error = " + errorCode.ToString("x", NumberFormatInfo.InvariantInfo));
                throw new Win32Exception(errorCode);
            }

            if (securityBuffer[1].type != realDataType)
                throw new InternalException();

            newOffset = securityBuffer[1].offset;
            return securityBuffer[1].size;
        }

        public static int VerifySignature(SafeDeleteContext securityContext, byte[] buffer, int offset, int count)
        {
            // setup security buffers for ssp call
            // one points at signed data
            // two will receive payload if signature is valid
            SecurityBuffer[] securityBuffer = new SecurityBuffer[2];
            securityBuffer[0] =
                new SecurityBuffer(buffer, offset, count, SecurityBufferType.Stream);
            securityBuffer[1] = new SecurityBuffer(0, SecurityBufferType.Data);

            // call SSP function
            int errorCode = SSPIWrapper.VerifySignature(
                                GlobalSSPI.SSPIAuth,
                                securityContext,
                                securityBuffer,
                                0);

            // throw if error
            if (errorCode != 0)
            {
                GlobalLog.Print(
                            "NTAuthentication#" +
                            ValidationHelper.HashString(securityContext) +
                            "::VerifySignature() threw Error = " +
                            errorCode.ToString("x",
                                NumberFormatInfo.InvariantInfo));
                throw new Win32Exception(errorCode);
            }

            // not sure why this is here - retained from Encrypt code above
            if (securityBuffer[1].type != SecurityBufferType.Data)
                throw new InternalException();

            // return validated payload size 
            return securityBuffer[1].size;
        }

        public static int MakeSignature(SafeDeleteContext securityContext, object secSizes, byte[] buffer, int offset, int count, ref byte[] output)
        {
            SecSizes sizes = secSizes as SecSizes;

            // alloc new output buffer if not supplied or too small
            int resultSize = count + sizes.MaxSignature;
            if (output == null || output.Length < resultSize)
            {
                output = new byte[resultSize];
            }

            // make a copy of user data for in-place encryption
            Buffer.BlockCopy(buffer, offset, output, sizes.MaxSignature, count);

            // setup security buffers for ssp call
            SecurityBuffer[] securityBuffer = new SecurityBuffer[2];
            securityBuffer[0] = new SecurityBuffer(output, 0, sizes.MaxSignature, SecurityBufferType.Token);
            securityBuffer[1] = new SecurityBuffer(output, sizes.MaxSignature, count, SecurityBufferType.Data);

            // call SSP Function
            int errorCode = SSPIWrapper.MakeSignature(
                                GlobalSSPI.SSPIAuth,
                                securityContext,
                                securityBuffer,
                                0);

            // throw if error
            if (errorCode != 0)
            {
                GlobalLog.Print(
                    "NTAuthentication#" +
                    ValidationHelper.HashString(securityContext) +
                    "::Encrypt() throw Error = " +
                    errorCode.ToString("x", NumberFormatInfo.InvariantInfo));
                throw new Win32Exception(errorCode);
            }

            // return signed size
            return securityBuffer[0].size + securityBuffer[1].size;
        }

        public static object QueryContextSecuritySizes(SafeDeleteContext securityContext)
        {
            return SSPIWrapper.QueryContextAttributes(
                GlobalSSPI.SSPIAuth,
                securityContext,
                Interop.Secur32.ContextAttribute.Sizes);
        }

        public static string QueryContextClientSpecifiedSpn(SafeDeleteContext securityContext)
        {
            return SSPIWrapper.QueryContextAttributes(GlobalSSPI.SSPIAuth, securityContext,
                Interop.Secur32.ContextAttribute.ClientSpecifiedSpn) as string;
        }

        public static string QueryContextClientSpecifiedSpn(SafeDeleteContext securityContext, out SecurityStatusPal errorCode)
        {
            int win32Error;
            string result = SSPIWrapper.QueryContextAttributes(GlobalSSPI.SSPIAuth, securityContext,
                Interop.Secur32.ContextAttribute.ClientSpecifiedSpn, out win32Error) as string;
            errorCode = SslStreamPal.GetSecurityStatusPalFromWin32Int(win32Error);
            return result;
        }

        public static string QueryContextAssociatedName(SafeDeleteContext securityContext)
        {
            return SSPIWrapper.QueryContextAttributes(
                GlobalSSPI.SSPIAuth,
                securityContext,
                Interop.Secur32.ContextAttribute.Names) as string;
        }

        public static NegotiationInfoClass QueryContextNegotiationInfo(SafeDeleteContext securityContext)
        {
            return SSPIWrapper.QueryContextAttributes(GlobalSSPI.SSPIAuth, securityContext,
                Interop.Secur32.ContextAttribute.NegotiationInfo) as NegotiationInfoClass;
        }

        private static ContextFlags GetContextFlagsPalFromInterop(Interop.Secur32.ContextFlags win32Flags)
        {
            ContextFlags flags = ContextFlags.Zero;
            if ((win32Flags & Interop.Secur32.ContextFlags.AcceptExtendedError) != 0)
            {
                flags |= ContextFlags.AcceptExtendedError;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.AcceptIdentify) != 0)
            {
                flags |= ContextFlags.AcceptIdentify;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.AcceptIntegrity) != 0)
            {
                flags |= ContextFlags.AcceptIntegrity;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.AcceptStream) != 0)
            {
                flags |= ContextFlags.AcceptStream;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.AllocateMemory) != 0)
            {
                flags |= ContextFlags.AllocateMemory;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.AllowMissingBindings) != 0)
            {
                flags |= ContextFlags.AllowMissingBindings;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.Confidentiality) != 0)
            {
                flags |= ContextFlags.Confidentiality;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.Connection) != 0)
            {
                flags |= ContextFlags.Connection;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.Delegate) != 0)
            {
                flags |= ContextFlags.Delegate;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.InitExtendedError) != 0)
            {
                flags |= ContextFlags.InitExtendedError;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.InitIdentify) != 0)
            {
                flags |= ContextFlags.InitIdentify;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.InitIntegrity) != 0)
            {
                flags |= ContextFlags.InitIntegrity;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.InitManualCredValidation) != 0)
            {
                flags |= ContextFlags.InitManualCredValidation;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.InitStream) != 0)
            {
                flags |= ContextFlags.InitStream;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.InitUseSuppliedCreds) != 0)
            {
                flags |= ContextFlags.InitUseSuppliedCreds;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.MutualAuth) != 0)
            {
                flags |= ContextFlags.MutualAuth;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.ProxyBindings) != 0)
            {
                flags |= ContextFlags.ProxyBindings;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.ReplayDetect) != 0)
            {
                flags |= ContextFlags.ReplayDetect;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.SequenceDetect) != 0)
            {
                flags |= ContextFlags.SequenceDetect;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.UnverifiedTargetName) != 0)
            {
                flags |= ContextFlags.UnverifiedTargetName;
            }
            if ((win32Flags & Interop.Secur32.ContextFlags.UseSessionKey) != 0)
            {
                flags |= ContextFlags.UseSessionKey;
            }
            return flags;
        }

        private static Interop.Secur32.ContextFlags GetInteropFromContextFlagsPal(ContextFlags flags)
        {
            Interop.Secur32.ContextFlags win32Flags = Interop.Secur32.ContextFlags.Zero;
            if ((flags & ContextFlags.AcceptExtendedError) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.AcceptExtendedError;
            }
            if ((flags & ContextFlags.AcceptIdentify) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.AcceptIdentify;
            }
            if ((flags & ContextFlags.AcceptIntegrity) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.AcceptIntegrity;
            }
            if ((flags & ContextFlags.AcceptStream) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.AcceptStream;
            }
            if ((flags & ContextFlags.AllocateMemory) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.AllocateMemory;
            }
            if ((flags & ContextFlags.AllowMissingBindings) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.AllowMissingBindings;
            }
            if ((flags & ContextFlags.Confidentiality) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.Confidentiality;
            }
            if ((flags & ContextFlags.Connection) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.Connection;
            }
            if ((flags & ContextFlags.Delegate) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.Delegate;
            }
            if ((flags & ContextFlags.InitExtendedError) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.InitExtendedError;
            }
            if ((flags & ContextFlags.InitIdentify) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.InitIdentify;
            }
            if ((flags & ContextFlags.InitIntegrity) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.InitIntegrity;
            }
            if ((flags & ContextFlags.InitManualCredValidation) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.InitManualCredValidation;
            }
            if ((flags & ContextFlags.InitStream) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.InitStream;
            }
            if ((flags & ContextFlags.InitUseSuppliedCreds) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.InitUseSuppliedCreds;
            }
            if ((flags & ContextFlags.MutualAuth) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.MutualAuth;
            }
            if ((flags & ContextFlags.ProxyBindings) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.ProxyBindings;
            }
            if ((flags & ContextFlags.ReplayDetect) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.ReplayDetect;
            }
            if ((flags & ContextFlags.SequenceDetect) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.SequenceDetect;
            }
            if ((flags & ContextFlags.UnverifiedTargetName) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.UnverifiedTargetName;
            }
            if ((flags & ContextFlags.UseSessionKey) != 0)
            {
                win32Flags |= Interop.Secur32.ContextFlags.UseSessionKey;
            }
            return win32Flags;
        }
    }
}
