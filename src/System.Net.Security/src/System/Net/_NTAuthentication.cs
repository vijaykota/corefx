// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;
using System.Threading;
using System.Globalization;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Principal;
using System.Net.Security;
using ValidationHelper = System.Net.Logging;

namespace System.Net
{
    internal class NTAuthentication
    {
#if false
        static private int s_UniqueGroupId = 1;
#endif
        static private ContextCallback s_InitializeCallback = new ContextCallback(InitializeCallback);

        private bool m_IsServer;

        private SafeFreeCredentials m_CredentialsHandle;
        private SafeDeleteContext m_SecurityContext;
        private string m_Spn;
        private string m_ClientSpecifiedSpn;

        private int m_TokenSize;
        private ContextFlags m_RequestedContextFlags;
        private ContextFlags m_ContextFlags;
        private string m_UniqueUserId;

        private bool m_IsCompleted;
        private string m_ProtocolName;
        private object m_Sizes;
        private string m_LastProtocolName;
        private string m_Package;

        private ChannelBinding m_ChannelBinding;

        //
        // Properties
        //
        internal string UniqueUserId
        {
            get
            {
                return m_UniqueUserId;
            }
        }

        // The semantic of this propoerty is "Don't call me again".
        // It can be completed either with success or error
        // The latest case is signalled by IsValidContext==false
        internal bool IsCompleted
        {
            get
            {
                return m_IsCompleted;
            }
        }

        internal bool IsValidContext
        {
            get
            {
                return !(m_SecurityContext == null || m_SecurityContext.IsInvalid);
            }
        }

        internal string AssociatedName
        {
            get
            {
                if (!(IsValidContext && IsCompleted))
                    throw new Exception(SR.net_auth_noauth);

                string name = NegotiateStreamPal.QueryContextAssociatedName(m_SecurityContext);
                GlobalLog.Print("NTAuthentication: The context is associated with [" + name + "]");
                return name;
            }
        }

        internal bool IsConfidentialityFlag
        {
            get
            {
                return (m_ContextFlags & ContextFlags.Confidentiality) != 0;
            }
        }

        internal bool IsIntegrityFlag
        {
            get
            {
                return (m_ContextFlags & (m_IsServer ? ContextFlags.AcceptIntegrity : ContextFlags.InitIntegrity)) != 0;
            }
        }

        internal bool IsMutualAuthFlag
        {
            get
            {
                return (m_ContextFlags & ContextFlags.MutualAuth) != 0;
            }
        }

        internal bool IsDelegationFlag
        {
            get
            {
                return (m_ContextFlags & ContextFlags.Delegate) != 0;
            }
        }

        internal bool IsIdentifyFlag
        {
            get
            {
                return (m_ContextFlags & (m_IsServer ? ContextFlags.AcceptIdentify : ContextFlags.InitIdentify)) != 0;
            }
        }

        internal string Spn
        {
            get
            {
                return m_Spn;
            }
        }

        internal string ClientSpecifiedSpn
        {
            get
            {
                if (m_ClientSpecifiedSpn == null)
                {
                    m_ClientSpecifiedSpn = GetClientSpecifiedSpn();
                }
                return m_ClientSpecifiedSpn;
            }
        }

        internal bool OSSupportsExtendedProtection
        {
            get
            {
                GlobalLog.Assert(IsCompleted && IsValidContext, "NTAuthentication#{0}::OSSupportsExtendedProtection|The context is not completed or invalid.", ValidationHelper.HashString(this));

                SecurityStatusPal errorCode;
                NegotiateStreamPal.QueryContextClientSpecifiedSpn(m_SecurityContext, out errorCode);

                // We consider any error other than Unsupported to mean that the underlying OS
                // supports extended protection.  Most likely it will be TargetUnknown.
                return (errorCode != SecurityStatusPal.Unsupported);
            }
        }

        //
        // True indicates this instance is for Server and will use AcceptSecurityContext SSPI API
        //
        internal bool IsServer
        {
            get
            {
                return m_IsServer;
            }
        }

        //
        internal bool IsKerberos
        {
            get
            {
                if (m_LastProtocolName == null)
                    m_LastProtocolName = ProtocolName;

                return (object)m_LastProtocolName == (object)NegotiationInfoClass.Kerberos;
            }
        }
        internal bool IsNTLM
        {
            get
            {
                if (m_LastProtocolName == null)
                    m_LastProtocolName = ProtocolName;

                return (object)m_LastProtocolName == (object)NegotiationInfoClass.NTLM;
            }
        }

        internal string Package
        {
            get
            {
                return m_Package;
            }
        }

        internal string ProtocolName
        {
            get
            {
                // NB: May return string.Empty if the auth is not done yet or failed
                if (m_ProtocolName == null)
                {
                    NegotiationInfoClass negotiationInfo = null;

                    if (IsValidContext)
                    {
                        negotiationInfo = NegotiateStreamPal.QueryContextNegotiationInfo(m_SecurityContext);
                        if (IsCompleted)
                        {
                            if (negotiationInfo != null)
                            {
                                //cache it only when it's completed
                                m_ProtocolName = negotiationInfo.AuthenticationPackage;
                            }
                        }
                    }
                    return negotiationInfo == null ? string.Empty : negotiationInfo.AuthenticationPackage;
                }
                return m_ProtocolName;
            }
        }

        internal object Sizes
        {
            get
            {
                GlobalLog.Assert(IsCompleted && IsValidContext, "NTAuthentication#{0}::MaxDataSize|The context is not completed or invalid.", ValidationHelper.HashString(this));
                if (m_Sizes == null)
                {
                    m_Sizes = NegotiateStreamPal.QueryContextSecuritySizes(m_SecurityContext);
                }
                return m_Sizes;
            }
        }

        internal ChannelBinding ChannelBinding
        {
            get { return m_ChannelBinding; }
        }

        //
        // .Ctors
        //

#if false
        //
        // Use only for client HTTP authentication
        //
        internal NTAuthentication(string package, NetworkCredential networkCredential, SpnToken spnToken,
                WebRequest request, ChannelBinding channelBinding) :
            this(false, package, networkCredential, spnToken.Spn, GetHttpContextFlags(request, spnToken.IsTrusted),
                request.GetWritingContext(), channelBinding)
        {
            //
            //  In order to prevent a race condition where one request could
            //  steal a connection from another request, before a handshake is
            //  complete, we create a new Group for each authentication request.
            //
            if (package == NtlmClient.AuthType || package == NegotiateClient.AuthType)
            {
                m_UniqueUserId = (Interlocked.Increment(ref s_UniqueGroupId)).ToString(NumberFormatInfo.InvariantInfo) + m_UniqueUserId;
            }
        }
        //
        private static ContextFlags GetHttpContextFlags(WebRequest request, bool trustedSpn)
        {
            ContextFlags contextFlags = ContextFlags.Connection;

            if (request.ImpersonationLevel == TokenImpersonationLevel.Anonymous)
                throw new NotSupportedException(SR.net_auth_no_anonymous_support);
            else if (request.ImpersonationLevel == TokenImpersonationLevel.Identification)
                contextFlags |= ContextFlags.InitIdentify;
            else if (request.ImpersonationLevel == TokenImpersonationLevel.Delegation)
                contextFlags |= ContextFlags.Delegate;

            if (request.AuthenticationLevel == AuthenticationLevel.MutualAuthRequested || request.AuthenticationLevel == AuthenticationLevel.MutualAuthRequired)
                contextFlags |= ContextFlags.MutualAuth;

            // CBT: If the SPN came from an untrusted source we should tell the server by setting this flag
            if (!trustedSpn && ComNetOS.IsWin7Sp1orLater)
                contextFlags |= ContextFlags.UnverifiedTargetName;

            return contextFlags;
        }
#endif

        //
        // This constructor is for a general (non-HTTP) authentication handshake using SSPI
        // Works for both client and server sides.
        //
#if false
        // Security: we may need to impersonate on user behalf as to temporarily restore original thread token.
        [SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.ControlPrincipal)]
#endif
        internal NTAuthentication(bool isServer, string package, NetworkCredential credential, string spn, ContextFlags requestedContextFlags, ContextAwareResult context, ChannelBinding channelBinding)
        {
            //
            // check if we're using DefaultCredentials
            //
            if (credential == CredentialCache.DefaultNetworkCredentials)
            {
                // CONSIDER: Change to a real runtime check that throws InvalidOperationException to help catch customer race conditions.
#if DEBUG
                GlobalLog.Assert(context == null || context.IdentityRequested, "NTAuthentication#{0}::.ctor|Authentication required when it wasn't expected.  (Maybe Credentials was changed on another thread?)", ValidationHelper.HashString(this));
#endif

                WindowsIdentity w = context == null ? null : context.Identity;
                try
                {
                    if (w != null)
                    {
                        WindowsIdentity.RunImpersonated(SafeAccessTokenHandle.InvalidHandle, () =>
                        {
                            Initialize(isServer, package, credential, spn, requestedContextFlags, channelBinding);
                        });
                    }
                    else
                    {
                        ExecutionContext x = context == null ? null : context.ContextCopy;
                        if (x == null)
                        {
                            Initialize(isServer, package, credential, spn, requestedContextFlags, channelBinding);
                        }
                        else
                        {
                            ExecutionContext.Run(x, s_InitializeCallback, new InitializeCallbackContext(this, isServer, package, credential, spn, requestedContextFlags, channelBinding));
                        }
                    }
                }
                catch
                {
                    // Prevent the impersonation from leaking to upstack exception filters.
                    throw;
                }
            }
            else
            {
                Initialize(isServer, package, credential, spn, requestedContextFlags, channelBinding);
            }
        }

        //
        // This overload does not attmept to impersonate because the caller either did it already or the original thread context is still preserved
        //
        internal NTAuthentication(bool isServer, string package, NetworkCredential credential, string spn, ContextFlags requestedContextFlags, ChannelBinding channelBinding)
        {
            Initialize(isServer, package, credential, spn, requestedContextFlags, channelBinding);
        }

        //
        // This overload always uses the default credentials for the process.
        //
#if false
        [SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.ControlPrincipal)]
#endif
        internal NTAuthentication(bool isServer, string package, string spn, ContextFlags requestedContextFlags, ChannelBinding channelBinding)
        {
            try
            {
                WindowsIdentity.RunImpersonated(SafeAccessTokenHandle.InvalidHandle, () =>
                {
                    Initialize(isServer, package, CredentialCache.DefaultNetworkCredentials, spn, requestedContextFlags,
                        channelBinding);
                });
            }
            catch
            {
                // Avoid exception filter attacks.
                throw;
            }
        }

        private class InitializeCallbackContext
        {
            internal InitializeCallbackContext(NTAuthentication thisPtr, bool isServer, string package, NetworkCredential credential, string spn, ContextFlags requestedContextFlags, ChannelBinding channelBinding)
            {
                this.thisPtr = thisPtr;
                this.isServer = isServer;
                this.package = package;
                this.credential = credential;
                this.spn = spn;
                this.requestedContextFlags = requestedContextFlags;
                this.channelBinding = channelBinding;
            }

            internal readonly NTAuthentication thisPtr;
            internal readonly bool isServer;
            internal readonly string package;
            internal readonly NetworkCredential credential;
            internal readonly string spn;
            internal readonly ContextFlags requestedContextFlags;
            internal readonly ChannelBinding channelBinding;
        }

        private static void InitializeCallback(object state)
        {
            InitializeCallbackContext context = (InitializeCallbackContext)state;
            context.thisPtr.Initialize(context.isServer, context.package, context.credential, context.spn, context.requestedContextFlags, context.channelBinding);
        }

        //
        private void Initialize(bool isServer, string package, NetworkCredential credential, string spn, ContextFlags requestedContextFlags, ChannelBinding channelBinding)
        {
            GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(this) + "::.ctor() package:" + package + " spn:" + spn + " flags :" + requestedContextFlags);
            m_TokenSize = NegotiateStreamPal.GetMaxTokenSize(package);
            m_IsServer = isServer;
            m_Spn = spn;
            m_SecurityContext = null;
            m_RequestedContextFlags = requestedContextFlags;
            m_Package = package;
            m_ChannelBinding = channelBinding;

            GlobalLog.Print("Peer SPN-> '" + m_Spn + "'");
            //
            // check if we're using DefaultCredentials
            //
            if (credential == CredentialCache.DefaultNetworkCredentials)
            {
                GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(this) + "::.ctor(): using DefaultCredentials");
                m_CredentialsHandle = NegotiateStreamPal.AcquireDefaultCredential(package, m_IsServer);
                m_UniqueUserId = "/S"; // save off for unique connection marking ONLY used by HTTP client
            }
            else
            {
                m_CredentialsHandle = NegotiateStreamPal.AcquireCredentialsHandle(package, m_IsServer, credential.UserName, credential.Password, credential.Domain);
            }
#if false
            // Code for handling OS before Windows 7
            else
            {
                //
                // we're not using DefaultCredentials, we need a
                // AuthIdentity struct to contain credentials
                // SECREVIEW:
                // we'll save username/domain in temp strings, to avoid decrypting multiple times.
                // password is only used once
                //
                string username = credential.InternalGetUserName();

                string domain = credential.InternalGetDomain();
                // ATTN:
                // NetworkCredential class does not differentiate between null and "" but SSPI packages treat these cases differently
                // For NTLM we want to keep "" for Wdigest.Dll we should use null.
                m_UniqueUserId = domain + "/" + username + "/U"; // save off for unique connection marking ONLY used by HTTP client
                domain = (object) package == (object) NegotiationInfoClass.WDigest && (domain == null || domain.Length == 0)
                    ? null
                    : domain;

                GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(this) + "::.ctor(): using authIdentity:" + authIdentity.ToString());

                m_CredentialsHandle = NegotiateStreamPal.AcquireCredentialsHandle(package, m_IsServer, false,
                    username, credential.InternalGetPassword(), domain);
            }
#endif
        }

        //
        // Methods
        //

        internal SafeDeleteContext GetValidCompletedContext()
        {
            if (!(IsValidContext && IsCompleted))
            {
                return null;
            }
            return m_SecurityContext;
        }

        internal void CloseContext()
        {
            if (m_SecurityContext != null && !m_SecurityContext.IsInvalid)
                m_SecurityContext.Dispose();
        }

        //
        // NTAuth::GetOutgoingBlob()
        // Created:   12-01-1999: L.M.
        // Description:
        // Accepts a base64 encoded incoming security blob and returns
        // a base 64 encoded outgoing security blob
        //
        // This method is for HttpWebRequest usage only as it has semantic bound to it
        internal string GetOutgoingBlob(string incomingBlob)
        {
            GlobalLog.Enter("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingBlob", incomingBlob);
            byte[] decodedIncomingBlob = null;
            if (incomingBlob != null && incomingBlob.Length > 0)
            {
                decodedIncomingBlob = Convert.FromBase64String(incomingBlob);
            }
            byte[] decodedOutgoingBlob = null;

            if ((IsValidContext || IsCompleted) && decodedIncomingBlob == null)
            {
                // we tried auth previously, now we got a null blob, we're done. this happens
                // with Kerberos & valid credentials on the domain but no ACLs on the resource
                GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingBlob() null blob AND m_SecurityContext#" + ValidationHelper.HashString(m_SecurityContext) + "::Handle:[0x" + m_SecurityContext.ToString() + "]");
                m_IsCompleted = true;
            }
            else
            {
                SecurityStatusPal statusCode;
#if TRAVE
                try
                {
#endif
                    decodedOutgoingBlob = GetOutgoingBlob(decodedIncomingBlob, true, out statusCode);
#if TRAVE
                }
                catch (Exception exception)
                {
                    if (NclUtilities.IsFatal(exception)) throw;

                    GlobalLog.LeaveException("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingBlob", exception);
                    throw;
                }
#endif
            }

            string outgoingBlob = null;
            if (decodedOutgoingBlob != null && decodedOutgoingBlob.Length > 0)
            {
                outgoingBlob = Convert.ToBase64String(decodedOutgoingBlob);
            }

            //This is only for HttpWebRequest that does not need security context anymore
            if (IsCompleted)
            {
                string name = ProtocolName; // cache the only info needed from a completed context before closing it
                CloseContext();
            }
            GlobalLog.Leave("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingBlob", outgoingBlob);
            return outgoingBlob;
        }

        // NTAuth::GetOutgoingBlob()
        // Created:   12-01-1999: L.M.
        // Description:
        // Accepts an incoming binary security blob  and returns
        // an outgoing binary security blob
        internal byte[] GetOutgoingBlob(byte[] incomingBlob, bool throwOnError, out SecurityStatusPal statusCode)
        {
            GlobalLog.Enter("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingBlob", ((incomingBlob == null) ? "0" : incomingBlob.Length.ToString(NumberFormatInfo.InvariantInfo)) + " bytes");

            List<SecurityBuffer> list = new List<SecurityBuffer>(2);

            if (incomingBlob != null)
            {
                list.Add(new SecurityBuffer(incomingBlob, SecurityBufferType.Token));
            }
            if (m_ChannelBinding != null)
            {
                list.Add(new SecurityBuffer(m_ChannelBinding));
            }

            SecurityBuffer[] inSecurityBufferArray = null;
            if (list.Count > 0)
            {
                inSecurityBufferArray = list.ToArray();
            }

            SecurityBuffer outSecurityBuffer = new SecurityBuffer(m_TokenSize, SecurityBufferType.Token);

            bool firstTime = m_SecurityContext == null;
            try
            {
                if (!m_IsServer)
                {
                    // client session
                    statusCode = NegotiateStreamPal.InitializeSecurityContext(
                        m_CredentialsHandle,
                        ref m_SecurityContext,
                        m_Spn,
                        m_RequestedContextFlags,
                        inSecurityBufferArray,
                        outSecurityBuffer,
                        ref m_ContextFlags);

                    GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingBlob() SSPIWrapper.InitializeSecurityContext() returns statusCode:0x" + ((int)statusCode).ToString("x8", NumberFormatInfo.InvariantInfo) + " (" + statusCode.ToString() + ")");

                    if (statusCode == SecurityStatusPal.CompleteNeeded)
                    {
                        SecurityBuffer[] inSecurityBuffers = new SecurityBuffer[1];
                        inSecurityBuffers[0] = outSecurityBuffer;

                        statusCode = NegotiateStreamPal.CompleteAuthToken(ref m_SecurityContext, inSecurityBuffers);

                        GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingDigestBlob() SSPIWrapper.CompleteAuthToken() returns statusCode:0x" + ((int)statusCode).ToString("x8", NumberFormatInfo.InvariantInfo) + " (" + statusCode.ToString() + ")");
                        outSecurityBuffer.token = null;
                    }
                }
                else
                {
                    // server session
                    statusCode = NegotiateStreamPal.AcceptSecurityContext(
                        m_CredentialsHandle,
                        ref m_SecurityContext,
                        m_RequestedContextFlags,
                        inSecurityBufferArray,
                        outSecurityBuffer,
                        ref m_ContextFlags);

                    GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingBlob() SSPIWrapper.AcceptSecurityContext() returns statusCode:0x" + ((int)statusCode).ToString("x8", NumberFormatInfo.InvariantInfo) + " (" + statusCode.ToString() + ")");
                }
            }
            finally
            {
                //
                // Assuming the ISC or ASC has referenced the credential on the first successful call,
                // we want to decrement the effective ref count by "disposing" it.
                // The real dispose will happen when the security context is closed.
                // Note if the first call was not successfull the handle is physically destroyed here
                //
                if (firstTime && m_CredentialsHandle != null)
                    m_CredentialsHandle.Dispose();
            }


            if (((int)statusCode >= (int)SecurityStatusPal.OutOfMemory))
            {
                CloseContext();
                m_IsCompleted = true;
                if (throwOnError)
                {
                    Exception exception = NegotiateStreamPal.CreateExceptionFromError(statusCode);
                    GlobalLog.Leave("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingBlob", "Win32Exception:" + exception);
                    throw exception;
                }
                GlobalLog.Leave("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingBlob", "null statusCode:0x" + ((int)statusCode).ToString("x8", NumberFormatInfo.InvariantInfo) + " (" + statusCode.ToString() + ")");
                return null;
            }
            else if (firstTime && m_CredentialsHandle != null)
            {
                // cache until it is pushed out by newly incoming handles
                SSPIHandleCache.CacheCredential(m_CredentialsHandle);
            }

            // the return value from SSPI will tell us correctly if the
            // handshake is over or not: http://msdn.microsoft.com/library/psdk/secspi/sspiref_67p0.htm
            // we also have to consider the case in which SSPI formed a new context, in this case we're done as well.
            if (statusCode == SecurityStatusPal.OK)
            {
                // we're sucessfully done
                GlobalLog.Assert(statusCode == SecurityStatusPal.OK, "NTAuthentication#{0}::GetOutgoingBlob()|statusCode:[0x{1:x8}] ({2}) m_SecurityContext#{3}::Handle:[{4}] [STATUS != OK]", ValidationHelper.HashString(this), (int)statusCode, statusCode, ValidationHelper.HashString(m_SecurityContext), m_SecurityContext.ToString());
                m_IsCompleted = true;
            }
            else
            {
                // we need to continue
                GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingBlob() need continue statusCode:[0x" + ((int)statusCode).ToString("x8", NumberFormatInfo.InvariantInfo) + "] (" + statusCode.ToString() + ") m_SecurityContext#" + ValidationHelper.HashString(m_SecurityContext) + "::Handle:" + m_SecurityContext + "]");
            }
            //            GlobalLog.Print("out token = " + outSecurityBuffer.ToString());
            //            GlobalLog.Dump(outSecurityBuffer.token);
            GlobalLog.Leave("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingBlob", "IsCompleted:" + IsCompleted.ToString());
            return outSecurityBuffer.token;
        }

#if false
        // for Server side (IIS 6.0) see: \\netindex\Sources\inetsrv\iis\iisrearc\iisplus\ulw3\digestprovider.cxx
        // for Client side (HTTP.SYS) see: \\netindex\Sources\net\http\sys\ucauth.c
        internal string GetOutgoingDigestBlob(string incomingBlob, string requestMethod, string requestedUri, string realm, bool isClientPreAuth, bool throwOnError, out SecurityStatus statusCode)
        {
            GlobalLog.Enter("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingDigestBlob", incomingBlob);

            // second time call with 3 incoming buffers to select HTTP client.
            // we should get back a SecurityStatus.OK and a non null outgoingBlob.
            SecurityBuffer[] inSecurityBuffers = null;
            SecurityBuffer outSecurityBuffer = new SecurityBuffer(m_TokenSize, isClientPreAuth ? BufferType.Parameters : BufferType.Token);

            bool firstTime = m_SecurityContext == null;
            try
            {
                if (!m_IsServer)
                {
                    // client session

                    if (!isClientPreAuth)
                    {
                        if (incomingBlob != null)
                        {
                            List<SecurityBuffer> list = new List<SecurityBuffer>(5);

                            list.Add(new SecurityBuffer(WebHeaderCollection.HeaderEncoding.GetBytes(incomingBlob), BufferType.Token));
                            list.Add(new SecurityBuffer(WebHeaderCollection.HeaderEncoding.GetBytes(requestMethod), BufferType.Parameters));
                            list.Add(new SecurityBuffer(null, BufferType.Parameters));
                            list.Add(new SecurityBuffer(Encoding.Unicode.GetBytes(m_Spn), BufferType.TargetHost));

                            if (m_ChannelBinding != null)
                            {
                                list.Add(new SecurityBuffer(m_ChannelBinding));
                            }

                            inSecurityBuffers = list.ToArray();
                        }

                        statusCode = (SecurityStatus)SSPIWrapper.InitializeSecurityContext(
                            GlobalSSPI.SSPIAuth,
                            m_CredentialsHandle,
                            ref m_SecurityContext,
                            requestedUri, // this must match the Uri in the HTTP status line for the current request
                            m_RequestedContextFlags,
                            Interop.Endianness.Network,
                            inSecurityBuffers,
                            outSecurityBuffer,
                            ref m_ContextFlags);

                        GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingDigestBlob() SSPIWrapper.InitializeSecurityContext() returns statusCode:0x" + ((int)statusCode).ToString("x8", NumberFormatInfo.InvariantInfo) + " (" + statusCode.ToString() + ")");
                    }
                    else
                    {
#if WDIGEST_PREAUTH
                        inSecurityBuffers = new SecurityBuffer[] {
                            new SecurityBuffer(null, BufferType.Token),
                            new SecurityBuffer(WebHeaderCollection.HeaderEncoding.GetBytes(requestMethod), BufferType.Parameters),
                            new SecurityBuffer(WebHeaderCollection.HeaderEncoding.GetBytes(requestedUri), BufferType.Parameters),
                            new SecurityBuffer(null, BufferType.Parameters),
                            outSecurityBuffer,
                        };

                        statusCode = (SecurityStatus)SSPIWrapper.MakeSignature(GlobalSSPI.SSPIAuth, m_SecurityContext, inSecurityBuffers, 0);

                        GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingDigestBlob() SSPIWrapper.MakeSignature() returns statusCode:0x" + ((int)statusCode).ToString("x8", NumberFormatInfo.InvariantInfo) + " (" + statusCode.ToString() + ")");
#else
                        statusCode = SecurityStatus.OK;
                        GlobalLog.Assert("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingDigestBlob()", "Invalid code path.");
#endif
                    }
                }
                else
                {
                    // server session
                    List<SecurityBuffer> list = new List<SecurityBuffer>(6);

                    list.Add(incomingBlob == null ? new SecurityBuffer(0, BufferType.Token) : new SecurityBuffer(WebHeaderCollection.HeaderEncoding.GetBytes(incomingBlob), BufferType.Token));
                    list.Add(requestMethod == null ? new SecurityBuffer(0, BufferType.Parameters) : new SecurityBuffer(WebHeaderCollection.HeaderEncoding.GetBytes(requestMethod), BufferType.Parameters));
                    list.Add(requestedUri == null ? new SecurityBuffer(0, BufferType.Parameters) : new SecurityBuffer(WebHeaderCollection.HeaderEncoding.GetBytes(requestedUri), BufferType.Parameters));
                    list.Add(new SecurityBuffer(0, BufferType.Parameters));
                    list.Add(realm == null ? new SecurityBuffer(0, BufferType.Parameters) : new SecurityBuffer(Encoding.Unicode.GetBytes(realm), BufferType.Parameters));

                    if (m_ChannelBinding != null)
                    {
                        list.Add(new SecurityBuffer(m_ChannelBinding));
                    }

                    inSecurityBuffers = list.ToArray();

                    statusCode = (SecurityStatus)SSPIWrapper.AcceptSecurityContext(
                        GlobalSSPI.SSPIAuth,
                        m_CredentialsHandle,
                        ref m_SecurityContext,
                        m_RequestedContextFlags,
                        Interop.Endianness.Network,
                        inSecurityBuffers,
                        outSecurityBuffer,
                        ref m_ContextFlags);

                    GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingDigestBlob() SSPIWrapper.AcceptSecurityContext() returns statusCode:0x" + ((int)statusCode).ToString("x8", NumberFormatInfo.InvariantInfo) + " (" + statusCode.ToString() + ")");

                    if (statusCode == SecurityStatus.CompleteNeeded)
                    {
                        inSecurityBuffers[4] = outSecurityBuffer;

                        statusCode = (SecurityStatus)SSPIWrapper.CompleteAuthToken(
                                GlobalSSPI.SSPIAuth,
                                ref m_SecurityContext,
                                inSecurityBuffers);

                        GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingDigestBlob() SSPIWrapper.CompleteAuthToken() returns statusCode:0x" + ((int)statusCode).ToString("x8", NumberFormatInfo.InvariantInfo) + " (" + statusCode.ToString() + ")");

                        outSecurityBuffer.token = null;
                    }
                }
            }
            finally
            {
                //
                // Assuming the ISC or ASC has referenced the credential on the first successful call,
                // we want to decrement the effective ref count by "disposing" it.
                // The real dispose will happen when the security context is closed.
                // Note if the first call was not successfull the handle is physically destroyed here
                //
                if (firstTime && m_CredentialsHandle != null)
                    m_CredentialsHandle.Close();
            }


            if (((int)statusCode & unchecked((int)0x80000000)) != 0)
            {
                CloseContext();
                if (throwOnError)
                {
                    Win32Exception exception = new Win32Exception((int)statusCode);
                    GlobalLog.Leave("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingDigestBlob", "Win32Exception:" + exception);
                    throw exception;
                }
                GlobalLog.Leave("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingDigestBlob", "null statusCode:0x" + ((int)statusCode).ToString("x8", NumberFormatInfo.InvariantInfo) + " (" + statusCode.ToString() + ")");
                return null;
            }
            else if (firstTime && m_CredentialsHandle != null)
            {
                // cache until it is pushed out by newly incoming handles
                SSPIHandleCache.CacheCredential(m_CredentialsHandle);
            }


            // the return value from SSPI will tell us correctly if the
            // handshake is over or not: http://msdn.microsoft.com/library/psdk/secspi/sspiref_67p0.htm
            if (statusCode == SecurityStatus.OK)
            {
                // we're done, cleanup
                m_IsCompleted = true;
            }
            else
            {
                // we need to continue
                GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingDigestBlob() need continue statusCode:[0x" + ((int)statusCode).ToString("x8", NumberFormatInfo.InvariantInfo) + "] (" + statusCode.ToString() + ") m_SecurityContext#" + ValidationHelper.HashString(m_SecurityContext) + "::Handle:" + ValidationHelper.ToString(m_SecurityContext) + "]");
            }
            GlobalLog.Print("out token = " + outSecurityBuffer.ToString());
            GlobalLog.Dump(outSecurityBuffer.token);
            GlobalLog.Print("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingDigestBlob() IsCompleted:" + IsCompleted.ToString());

            byte[] decodedOutgoingBlob = outSecurityBuffer.token;
            string outgoingBlob = null;
            if (decodedOutgoingBlob != null && decodedOutgoingBlob.Length > 0)
            {
                outgoingBlob = WebHeaderCollection.HeaderEncoding.GetString(decodedOutgoingBlob, 0, outSecurityBuffer.size);
            }
            GlobalLog.Leave("NTAuthentication#" + ValidationHelper.HashString(this) + "::GetOutgoingDigestBlob", outgoingBlob);
            return outgoingBlob;
        }
#endif

        internal int Encrypt(byte[] buffer, int offset, int count, ref byte[] output, uint sequenceNumber)
        {
            return NegotiateStreamPal.Encrypt(m_SecurityContext, Sizes, IsConfidentialityFlag, IsNTLM, buffer, offset, count,
                ref output, sequenceNumber);
        }

        internal int Decrypt(byte[] payload, int offset, int count, out int newOffset, uint expectedSeqNumber)
        {
            return NegotiateStreamPal.Decrypt(m_SecurityContext, IsConfidentialityFlag, IsNTLM, payload, offset, count,
                out newOffset, expectedSeqNumber);
        }

        private string GetClientSpecifiedSpn()
        {
            GlobalLog.Assert(IsValidContext && IsCompleted, "NTAuthentication: Trying to get the client SPN before handshaking is done!");

            string spn = NegotiateStreamPal.QueryContextClientSpecifiedSpn(m_SecurityContext);

            GlobalLog.Print("NTAuthentication: The client specified SPN is [" + spn + "]");
            return spn;
        }

        //
        // VerifySignature
        // 
        // Adapted from Decrypt method above as a more generic message 
        // signature verify method for SMTP AUTH GSSAPI (SASL). 
        // Decrypt method, used NegotiateStream, couldn't be used due 
        // to special cases for NTLM.
        // 
        // See SmtpNegotiateAuthenticationModule class for caller.
        // 
        internal int VerifySignature(byte[] buffer, int offset, int count)
        {
            // validate offset within length
            if (offset < 0 || offset > (buffer == null ? 0 : buffer.Length))
            {
                GlobalLog.Assert(
                            false,
                            "NTAuthentication#" +
                            ValidationHelper.HashString(this) +
                            "::VerifySignature",
                            "Argument 'offset' out of range.");
                throw new ArgumentOutOfRangeException("offset");
            }

            // validate count within offset and end of buffer
            if (count < 0 ||
                count > (buffer == null ? 0 : buffer.Length - offset))
            {
                GlobalLog.Assert(
                            false,
                            "NTAuthentication#" +
                            ValidationHelper.HashString(this) +
                            "::VerifySignature",
                            "Argument 'count' out of range.");
                throw new ArgumentOutOfRangeException("count");
            }

            return NegotiateStreamPal.VerifySignature(m_SecurityContext, buffer, offset, count);
        }

        //
        // MakeSignature
        // 
        // Adapted from Encrypt method above as a more generic message 
        // signing method for SMTP AUTH GSSAPI (SASL). 
        // Encrypt method, used for NegotiateStream, put size at head of
        // message.  Don't need that
        // 
        // See SmtpNegotiateAuthenticationModule class for caller.
        // 
        internal int MakeSignature(
                        byte[] buffer,
                        int offset,
                        int count,
                        ref byte[] output)
        {
            return NegotiateStreamPal.MakeSignature(m_SecurityContext, Sizes, buffer, offset, count, ref output);
        }
    }
}
