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
            if (context == null)
            {
                context = new SafeDeleteNegoContext(credential);
            }

            SafeDeleteNegoContext negoContext = (SafeDeleteNegoContext)context;
            SafeGssContextHandle contextHandle = negoContext.GssContext;

            uint outputFlags;
            Interop.NetSecurity.GssFlags inputFlags = GetInteropGssFromContextFlagsPal(inFlags);
            bool done = Interop.NetSecurity.EstablishSecurityContext(
                              ref contextHandle,
                              credential.GssCredential,
                              true,
                              negoContext.TargetName,
                              inputFlags,
                              ((inputBuffer != null) ? inputBuffer.token : null),
                              out outputBuffer.token,
                              out outputFlags);

            outFlags = GetContextFlagsPalFromInteropGss((Interop.NetSecurity.GssFlags)outputFlags);

            // Save the inner context handle for further calls to NetSecurity
            if (null == negoContext.GssContext)
            {
                negoContext.SetGssContext(contextHandle, true);
            }

            return done;
        }
    }
}
