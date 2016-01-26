using Microsoft.Win32.SafeHandles;

namespace System.Net.Security
{
    internal partial class NegoState
    {
        private static bool EstablishNtlmSecurityContext(
          SafeFreeNegoCredentials credential,
          ref SafeDeleteContext context,
          string targetName,
          ContextFlagsPal inFlags,
          SecurityBuffer inputBuffer,
          SecurityBuffer outputBuffer,
          ref ContextFlagsPal outFlags)
        {
            bool retVal;
            Interop.NetSecurity.NtlmFlags flags;

            if (null == context)
            {
                flags = GetInteropNtlmFromContextFlagsPal(inFlags);
                context = new SafeDeleteNegoContext(credential, flags);
                outputBuffer.token = Interop.NetSecurity.CreateNegotiateMessage((uint)flags);
                retVal = false;
            }
            else
            {
                SafeDeleteNegoContext negoContext = (SafeDeleteNegoContext)context;
                flags = negoContext.Flags;
                SafeNtlmBufferHandle sessionKey;
                outputBuffer.token = Interop.NetSecurity.CreateAuthenticateMessage(
                    (uint)flags,
                    credential.UserName,
                    credential.Password,
                    credential.Domain,
                    inputBuffer.token,
                    inputBuffer.offset,
                    inputBuffer.size,
                    out sessionKey);
                using (sessionKey)
                {
                    negoContext.SetKeys(sessionKey);
                }
                retVal = true;
            }
            outFlags = inFlags;
            outputBuffer.size = outputBuffer.token.Length;
            return retVal;
        }

        private static ContextFlagsPal GetContextFlagsPalFromInteropNtlm(Interop.NetSecurity.NtlmFlags ntlmFlags)
        {
            ContextFlagsPal flags = ContextFlagsPal.Zero;
            if ((ntlmFlags & Interop.NetSecurity.NtlmFlags.NTLMSSP_NEGOTIATE_SEAL) != 0)
            {
                flags |= ContextFlagsPal.Confidentiality;
            }
            if ((ntlmFlags & Interop.NetSecurity.NtlmFlags.NTLMSSP_NEGOTIATE_SIGN) != 0)
            {
                flags |= ContextFlagsPal.InitIntegrity;    // No NTLM server support
                flags |= ContextFlagsPal.ReplayDetect | ContextFlagsPal.SequenceDetect;
            }
            return flags;
        }

        private static Interop.NetSecurity.NtlmFlags GetInteropNtlmFromContextFlagsPal(ContextFlagsPal flags)
        {
            Interop.NetSecurity.NtlmFlags ntlmFlags = Interop.NetSecurity.NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE | Interop.NetSecurity.NtlmFlags.NTLMSSP_REQUEST_TARGET;
            if ((flags & (ContextFlagsPal.AcceptIntegrity | ContextFlagsPal.InitIntegrity | ContextFlagsPal.Confidentiality)) != 0)
            {
                ntlmFlags |= Interop.NetSecurity.NtlmFlags.NTLMSSP_NEGOTIATE_SIGN
                    | Interop.NetSecurity.NtlmFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN
                    | Interop.NetSecurity.NtlmFlags.NTLMSSP_NEGOTIATE_NTLM
                    | Interop.NetSecurity.NtlmFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
                    | Interop.NetSecurity.NtlmFlags.NTLMSSP_NEGOTIATE_128
                    | Interop.NetSecurity.NtlmFlags.NTLMSSP_NEGOTIATE_KEY_EXCH;
            }
            if ((flags & ContextFlagsPal.Confidentiality) != 0)
            {
                ntlmFlags |= Interop.NetSecurity.NtlmFlags.NTLMSSP_NEGOTIATE_SEAL;
            }
            return ntlmFlags;
        }
    }
}
