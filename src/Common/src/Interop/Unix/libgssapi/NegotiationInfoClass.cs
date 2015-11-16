// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.Net
{
    // we keep it simple since we use this only to know if NTLM or
    // Kerberos are used in the context of a Negotiate handshake
    internal class NegotiationInfoClass
    {
        internal const string NTLM = "NTLM";
        internal const string Kerberos = "Kerberos";
        internal const string Negotiate = "Negotiate";
        internal string AuthenticationPackage;

        internal NegotiationInfoClass(bool isNtlm)
        {
            AuthenticationPackage = isNtlm ? NTLM : Kerberos;
        }
    }
}
