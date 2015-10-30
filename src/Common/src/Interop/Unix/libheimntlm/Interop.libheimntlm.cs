// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;

using size_t = System.IntPtr;

internal static partial class Interop
{
    internal static partial class Libraries
    {
        // TODO (Issue #3717): Figure out the correct library on OSX
        internal const string LibHeimNtlm = "libheimntlm.so.0";
    }

    internal static partial class libheimntlm
    {
        [DllImport(Interop.Libraries.LibHeimNtlm)]
        internal static extern int heim_ntlm_free_buf(
            ref ntlm_buf data);

        [DllImport(Interop.Libraries.LibHeimNtlm)]
        internal static extern int heim_ntlm_encode_type1(
            ref ntlm_type1 type1,
            SafeNtlmBufferHandle data);

        [DllImport(Interop.Libraries.LibHeimNtlm)]
        internal static extern int heim_ntlm_decode_type2(
            SafeNtlmBufferHandle data,
            ref ntlm_type2 type2);

        [DllImport(Interop.Libraries.LibHeimNtlm)]
        internal static extern int heim_ntlm_free_type2(
            IntPtr type2);

        [DllImport(Interop.Libraries.LibHeimNtlm, CharSet = CharSet.Ansi)]
        internal static extern unsafe int heim_ntlm_nt_key(
            string password,
            SafeNtlmBufferHandle key);

        [DllImport(Interop.Libraries.LibHeimNtlm, CharSet=CharSet.Ansi)]
        internal static extern unsafe int heim_ntlm_calculate_lm2(
            IntPtr key,
            size_t len,
            string username,
            string target,
            byte* serverchallenge,
            byte* ntlmv2,
            SafeNtlmBufferHandle answer);

        [DllImport(Interop.Libraries.LibHeimNtlm)]
        internal static extern unsafe int heim_ntlm_calculate_ntlm1(
            IntPtr key,
            size_t len,
            byte* serverchallenge,
            SafeNtlmBufferHandle answer);

        [DllImport(Interop.Libraries.LibHeimNtlm, CharSet = CharSet.Ansi)]
        internal static extern unsafe int heim_ntlm_calculate_ntlm2(
            IntPtr key,
            size_t len,
            string username,
            string target,
            byte* serverchallenge,
            SafeNtlmBufferHandle infotarget,
            byte* ntlmv2,
            SafeNtlmBufferHandle answer);

        [DllImport(Interop.Libraries.LibHeimNtlm)]
        internal static extern int heim_ntlm_encode_type3(
            ref ntlm_type3 type3,
            SafeNtlmBufferHandle data,
            ref size_t mic_offset);

        [DllImport(Interop.Libraries.LibHeimNtlm)]
        internal static extern unsafe int heim_ntlm_build_ntlm1_master(
            byte* key,
            size_t len,
            SafeNtlmBufferHandle session,
            SafeNtlmBufferHandle master);

        // This is not yet available in libheimntlm
        internal static unsafe void heim_ntlm_build_ntlm2_master(
            byte* key,
            size_t len,
            SafeNtlmBufferHandle blob,
            SafeNtlmBufferHandle session,
            out SafeNtlmBufferHandle master)
        {
            byte[] exchangeKey = HMACDigest(key, (int)len, (byte*)blob.Value.ToPointer(), (int)blob.Length, null, 0);
            fixed (byte* keyPtr = exchangeKey)
            {
                using (SafeNtlmBufferHandle tempMaster = new SafeNtlmBufferHandle())
                {
                    int status = heim_ntlm_build_ntlm1_master(keyPtr, (size_t) exchangeKey.Length, session, tempMaster);
                    HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_build_ntlm1_master failed",
                        status);
                }

                byte[] exportKey = EVPEncryptOrDecrypt(true, keyPtr, exchangeKey.Length, (byte*)session.Value.ToPointer(), (int)session.Length);
                master = new SafeNtlmBufferHandle(exportKey);
            }
        }

    }
}
