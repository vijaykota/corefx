using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;

namespace System.Net.Security.Tests
{
    // TODO: Make these changse in KDCSetup defined in KerberosTest.cs
    public partial class KDCSetup
    {
        // TODO: This file name will change in PR 5919
        private const string NtlmShim = "System.Net.Security.Native.so";

        public static bool CheckAndInitializeNtlm(bool isKrbAvailable)
        {

            // TODO: Create temporary files
            // TODO: Define constants
            var password = "/tmp/mypassword";
            var cache = "/tmp/mycache";
            var cacheSwitch = " -c FILE:" + cache;
            Environment.SetEnvironmentVariable("NTLM_ACCEPTOR_CCACHE", cache);
            RunProcess("kdestroy", cacheSwitch);
            File.Delete(cache);
            RunProcess("kinit", cacheSwitch + " --password-file=" + password + " digestserver@TEST.H5L.SE"); // TODO: replace with correct values
            RunProcess("klist", cacheSwitch); // TODO: Only for debugging
            return isKrbAvailable && File.Exists(NtlmShim);
            // TODO: Clean up required for the temp files
        }

        // TODO: See if existing code can be reused
        private static bool RunProcess(string cmd, string args)
        {
            var processInfo = new System.Diagnostics.ProcessStartInfo(cmd);
            processInfo.FileName = cmd;
            processInfo.CreateNoWindow = true;
            processInfo.Arguments = args;
            using (var proc = System.Diagnostics.Process.Start(processInfo))
            {
                proc.WaitForExit();
                return proc.ExitCode == 0;
            }
        }
    }

    internal partial class UnixGssFakeNegotiateStream : NegotiateStream
    {
        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct NtlmBuffer : IDisposable
        {
            internal UInt64 length;
            internal IntPtr data;
            internal byte[] ToByteArray()
            {
                if (data == IntPtr.Zero || length == 0)
                {
                    return Array.Empty<byte>();
                }

                int bufferLength = Convert.ToInt32(length);
                byte[] destination = new byte[bufferLength];
                Marshal.Copy(data, destination, 0, bufferLength);
                return destination;
            }

            public void Dispose()
            {
                if (data != IntPtr.Zero)
                {
                    ReleaseNtlmBuffer(data, length);
                    data = IntPtr.Zero;
                }

                length = 0;
            }
        }

        // TODO: Name of library/entrypoints will change in PR 5919
        // TODO: For some reason got compilation error abt Interop.Libraries being inaccessible
        [DllImport("System.Net.Security.Native", EntryPoint = "NetSecurityNative_ReleaseGssBuffer")]
        internal static extern void ReleaseNtlmBuffer(
            IntPtr bufferPtr,
            UInt64 length);

        [DllImport("System.Net.Security.Native", EntryPoint = "NetSecurityNative_AcceptSecContext")]
        internal static extern Interop.NetSecurityNative.Status AcceptNtlmSecContext(
            out Interop.NetSecurityNative.Status minorStatus,
            ref SafeGssContextHandle acceptContextHandle,
            byte[] inputBytes,
            int inputLength,
            ref NtlmBuffer token);

        [DllImport("System.Net.Security.Native", EntryPoint = "NetSecurityNative_DeleteSecContext")]
        internal static extern Interop.NetSecurityNative.Status DeleteNtlmSecContext(
            out Interop.NetSecurityNative.Status minorStatus,
            ref IntPtr contextHandle);

        [DllImport("System.Net.Security.Native", EntryPoint = "NetSecurityNative_Wrap")]
        internal static extern Interop.NetSecurityNative.Status NtlmWrap(
            out Interop.NetSecurityNative.Status minorStatus,
            SafeGssContextHandle contextHandle,
            bool isEncrypt,
            byte[] inputBytes,
            int offset,
            int count,
            ref NtlmBuffer outBuffer);

        [DllImport("System.Net.Security.Native", EntryPoint = "NetSecurityNative_Unwrap")]
        internal static extern Interop.NetSecurityNative.Status NtlmUnwrap(
            out Interop.NetSecurityNative.Status minorStatus,
            SafeGssContextHandle contextHandle,
            byte[] inputBytes,
            int offset,
            int count,
            ref NtlmBuffer outBuffer);

        private static readonly Encoding s_asciiEncoding = new ASCIIEncoding();

        private static bool EstablishSecurityContext(
            ref SafeGssContextHandle context,
            ref bool isNtlm,
            byte[] buffer,
            out byte[] outputBuffer)
        {
            outputBuffer = null;

            // EstablishSecurityContext is called multiple times in a session.
            // In each call, we need to pass the context handle from the previous call.
            // For the first call, the context handle will be null.
            if (context == null)
            {
                context = new SafeGssContextHandle();
                if (buffer != null)
                {
                    const string NtlmSignature = "NTLMSSP";
                    string prefix = (buffer.Length <= NtlmSignature.Length) ? null : s_asciiEncoding.GetString(buffer, 0, NtlmSignature.Length);
                    isNtlm = string.Equals(prefix, NtlmSignature);
                }
            }

            Interop.NetSecurityNative.Status status;
            Interop.NetSecurityNative.Status minorStatus;

            if (isNtlm)
            {
                NtlmBuffer token = default(NtlmBuffer);
                try
                {
                    status = AcceptNtlmSecContext(out minorStatus,
                                                  ref context,
                                                  buffer,
                                                  (buffer == null) ? 0 : buffer.Length,
                                                  ref token);
                    outputBuffer = token.ToByteArray();
                }
                finally
                {
                    token.Dispose();
                }
            }
            else
            {
                Interop.NetSecurityNative.GssBuffer token = default(Interop.NetSecurityNative.GssBuffer);
                try
                {
                    status = Interop.NetSecurityNative.AcceptSecContext(out minorStatus,
                                                                  ref context,
                                                                  buffer,
                                                                  (buffer == null) ? 0 : buffer.Length,
                                                                  ref token);
                    outputBuffer = token.ToByteArray();
                }
                finally
                {
                    token.Dispose();
                }
            }

            if ((status != Interop.NetSecurityNative.Status.GSS_S_COMPLETE) && (status != Interop.NetSecurityNative.Status.GSS_S_CONTINUE_NEEDED))
            {
                throw new Interop.NetSecurityNative.GssApiException(status, minorStatus);
            }

            return status == Interop.NetSecurityNative.Status.GSS_S_COMPLETE;
        }

        private static byte[] UnwrapMessage(SafeGssContextHandle context, bool isNtlm, byte[] message)
        {
            Interop.NetSecurityNative.Status status;
            Interop.NetSecurityNative.Status minorStatus;
            byte[] outputBuffer;

            if (isNtlm)
            {
                Console.WriteLine("Got ex in accept: {0}", message.Length); // TODO: FOr debugging
                NtlmBuffer unwrapped = default(NtlmBuffer);
                try
                {
                    status = NtlmUnwrap(out minorStatus,
                                        context,
                                        message,
                                        0,
                                        message.Length,
                                        ref unwrapped);
                    outputBuffer = unwrapped.ToByteArray();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Got ex in accept: {0}", ex); // TODO: FOr debugging
                    throw;
                }
                finally
                {
                    unwrapped.Dispose();
                }
            }
            else
            {
                Interop.NetSecurityNative.GssBuffer unwrapped = default(Interop.NetSecurityNative.GssBuffer);
                try
                {
                    status = Interop.NetSecurityNative.Unwrap(out minorStatus,
                                                          context,
                                                          message,
                                                          0,
                                                          message.Length,
                                                          ref unwrapped);
                    outputBuffer = unwrapped.ToByteArray();
                }
                finally
                {
                    unwrapped.Dispose();
                }
            }
            if (status != Interop.NetSecurityNative.Status.GSS_S_COMPLETE)
            {
                throw new Interop.NetSecurityNative.GssApiException(status, minorStatus);
            }
            return outputBuffer;
        }

        private static byte[] WrapMessage(SafeGssContextHandle context, bool isNtlm, byte[] message)
        {
            Interop.NetSecurityNative.Status status;
            Interop.NetSecurityNative.Status minorStatus;
            byte[] outputBuffer;

            if (isNtlm)
            {
                NtlmBuffer wrapped = default(NtlmBuffer);
                try
                {
                    status = NtlmWrap(out minorStatus,
                                      context,
                                      false,
                                      message,
                                      0,
                                      message.Length,
                                      ref wrapped);
                    outputBuffer = wrapped.ToByteArray();
                }
                finally
                {
                    wrapped.Dispose();
                }
            }
            else
            {
                Interop.NetSecurityNative.GssBuffer wrapped = default(Interop.NetSecurityNative.GssBuffer);
                try
                {
                    status = Interop.NetSecurityNative.Wrap(out minorStatus,
                                                            context,
                                                            false,
                                                            message,
                                                            0,
                                                            message.Length,
                                                            ref wrapped);
                    outputBuffer = wrapped.ToByteArray();
                }
                finally
                {
                    wrapped.Dispose();
                }
            }
            if (status != Interop.NetSecurityNative.Status.GSS_S_COMPLETE)
            {
                throw new Interop.NetSecurityNative.GssApiException(status, minorStatus);
            }
            return outputBuffer;
        }
    }
}


