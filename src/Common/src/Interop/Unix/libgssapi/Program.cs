using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

#if CODE_ANALYSIS
using System.Net.Security;
using System.Security.Principal;
#endif

namespace Sample
{
    using MockUtils;
#if CODE_ANALYSIS
    using MockNegotiateStream = System.Net.Security.NegotiateStream;
    using MockCredential = System.Net.NetworkCredential;
    using MockProtection = System.Net.Security.ProtectionLevel;
    using MockImpersonation = System.Security.Principal.TokenImpersonationLevel;
#else
    using MockNegotiateStream;
#endif
    public class Program
    {
        private static void TestNegotiateClient(MockCredential cred, string target, string server, int port)
        {
            using (var stream = new ClientStream(server, port))
            {
                var negoStream = new MockNegotiateStream(stream);
                var isNtlm = String.IsNullOrEmpty(target);
                var protectionLevel = MockProtection.EncryptAndSign;
#if CODE_ANALYSIS
                if (!isNtlm) cred = CredentialCache.DefaultNetworkCredentials; // to allow testing with real Windows logged-on credentials
                else protectionLevel = MockProtection.None; // reqd to force NTLM auth
#endif
                // Use WCF defaults for ChannelBinding & TokenImpersonationLevel
                negoStream.AuthenticateAsClient(cred, null, target, protectionLevel, MockImpersonation.Identification);
                MockLogging.PrintInfo(null, "____Connected to " + negoStream.RemoteIdentity.Name);
                var sendBuf = Encoding.UTF8.GetBytes("Hello " + (isNtlm ? "NTLMv2" : "SPNEGO") + "\n");
                negoStream.Write(sendBuf, 0, sendBuf.Length);
                MockLogging.PrintInfo(null, "Waiting for data from server....");
                var recvBuf = new byte[1000];
                var ret = negoStream.Read(recvBuf, 0, recvBuf.Length);
                MockLogging.Dump(null, null, "TestNegotiateClient", recvBuf, 0, ret);
            }
        }

        private static void TestNegotiateServer(MockCredential cred, int port)
        {
            using (var stream = new ServerStream(port))
            {
                var negoStream = new MockNegotiateStream(stream);
#if CODE_ANALYSIS
                // Use None protection to allow Windows NTLM client
                negoStream.AuthenticateAsServer(CredentialCache.DefaultNetworkCredentials, null, ProtectionLevel.None, TokenImpersonationLevel.Identification);
#else
                // Use WCF defaults for ExtendedProtectionPolic & TokenImpersonationLevel
                negoStream.AuthenticateAsServer(cred, null, impersonation: MockImpersonation.Identification);
#endif
                MockLogging.PrintInfo(null, "____Connected to " + negoStream.RemoteIdentity.Name);
                MockLogging.PrintInfo(null, "Waiting for data from client....");
                var recvBuf = new byte[1000];
                var ret = negoStream.Read(recvBuf, 0, recvBuf.Length);
                MockLogging.Dump(null, null, "TestNegotiateServer", recvBuf, 0, ret);
                negoStream.Write(recvBuf, 0, ret);
            }
        }

        private static void PrintUsage(string[] args)
        {
            MockLogging.PrintInfo(null, "\nWithout arguments, run in server mode");
            MockLogging.PrintInfo(null, "To run in client mode, pass targetname, username and password. Optionally pass server");
            MockLogging.PrintInfo(null, "\n\t eg: MockNego.exe");
            MockLogging.PrintInfo(null, "\t eg: MockNego.exe myservice/testbox.com@TESTBOX.REALM testuser password 1.2.3.4\n");
            MockLogging.PrintInfo(null, "Make sure that targetname is exactly how the SPN is defined on the KDC\n");
        }

        public static void Main(string[] args)
        {
            if(args == null || args.Length<1)
            {
                TestNegotiateServer(null, 0);
            }
#if false
            else if (args.Length == 1)
            {
                TestNegotiateServer(null, Int32.Parse(args[0]));
            }
#endif
            else if (args.Length >= 3)
            {
                var domain = args[0].Contains("@") ? string.Empty : args[0];
                var target = args[0].Contains("@") ? args[0] : string.Empty;
                var cred = new MockCredential
                {
                    UserName = args[1],
                    Password = args[2],
                    Domain = domain,
                };
                var server = args.Length > 3 ? args[3] : null;
#if false
                var port = args.Length > 4 ? Int32.Parse(args[4]) : 0;
#endif
                TestNegotiateClient(cred, target, server, 0);
            }
            else
            {
                PrintUsage(args);
            }
        }  
    }
}
