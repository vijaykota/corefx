// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

using size_t = System.IntPtr;

internal static partial class Interop
{
    internal static partial class libheimntlm
    {
        #region To be shimmed
        // TODO (Issue: 3717) : Check or create shims
        [DllImport("libcrypto")]
        private static extern IntPtr EVP_MD_CTX_create();
        [DllImport("libcrypto")]
        private static extern void EVP_MD_CTX_destroy(IntPtr ctx);
        [DllImport("libcrypto")]
        private static extern IntPtr EVP_md5();
        [DllImport("libcrypto")]
        private static extern void EVP_DigestInit_ex(IntPtr ctx, IntPtr type, IntPtr impl);
        [DllImport("libcrypto")]
        private static unsafe extern void EVP_DigestUpdate(IntPtr ctx, byte* d, size_t cnt);
        [DllImport("libcrypto")]
        private static unsafe extern void EVP_DigestFinal_ex(IntPtr ctx, byte* md, out uint s);
        private const int EVP_MAX_MD_SIZE = 64;
        [StructLayout(LayoutKind.Sequential)]
        private struct EVP_MD_CTX
        {
            public IntPtr digest;
            public IntPtr engine;
            public ulong flags;
            public IntPtr md_data;
            public IntPtr pctx;
            public IntPtr update;
        }
        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct HMAC_CTX
        {
            public IntPtr md;
            public EVP_MD_CTX md_ctx;
            public EVP_MD_CTX i_ctx;
            public EVP_MD_CTX o_ctx;
            public uint key_length;
            public fixed byte key[128];
        }

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct RC4_KEY
        {
            public int x;
            public int y;
            public fixed int data[256];
        }

        private const int EVP_MAX_IV_LENGTH = 16;
        private const int EVP_MAX_BLOCK_LENGTH = 32;
        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct EVP_CIPHER_CTX
        {
            public IntPtr cipher;
            public IntPtr engine;
            public int encrypt;
            public int buf_len;
            public fixed byte oiv[EVP_MAX_IV_LENGTH];
            public fixed byte iv[EVP_MAX_IV_LENGTH];
            public fixed byte buf[EVP_MAX_BLOCK_LENGTH];
            public int num;
            public IntPtr app_data;
            public int key_len;
            public ulong flags;
            public IntPtr cipher_data;
            public int final_used;
            public int block_mask;
            private fixed byte final [EVP_MAX_BLOCK_LENGTH];
        }
        [DllImport("libcrypto")]
        private static extern void HMAC_CTX_init(ref HMAC_CTX ctx);
        [DllImport("libcrypto")]
        private static extern void HMAC_CTX_cleanup(ref HMAC_CTX ctx);
        [DllImport("libcrypto")]
        private static unsafe extern void HMAC_Init_ex(ref HMAC_CTX ctx, byte* key, int key_len, IntPtr md, IntPtr impl);
        [DllImport("libcrypto")]
        private static unsafe extern void HMAC_Update(ref HMAC_CTX ctx, byte* data, int len);
        [DllImport("libcrypto")]
        private static unsafe extern void HMAC_Final(ref HMAC_CTX ctx, byte* md, out uint len);
        [DllImport("libcrypto")]
        private static unsafe extern void RC4_set_key(ref RC4_KEY key, int len, byte* data);
        [DllImport("libcrypto")]
        private static unsafe extern void RC4(ref RC4_KEY key, ulong len, byte* indata, byte* outdata);
        [DllImport("libcrypto")]
        private static extern IntPtr EVP_rc4();
        [DllImport("libcrypto")]
        private static extern void EVP_CIPHER_CTX_init(ref EVP_CIPHER_CTX ctx);
        [DllImport("libcrypto")]
        private static extern int EVP_CIPHER_CTX_cleanup(ref EVP_CIPHER_CTX ctx);
        [DllImport("libcrypto")]
        private static unsafe extern void EVP_CipherInit_ex(ref EVP_CIPHER_CTX ctx, IntPtr type, IntPtr impl, byte* key, IntPtr iv, int enc);
        [DllImport("libcrypto")]
        private static unsafe extern int EVP_Cipher(ref EVP_CIPHER_CTX ctx, byte* output, byte* input, int inl);
        #endregion

        internal static unsafe RC4_KEY RC4Init(byte* key, int keylen)
        {
            RC4_KEY rc4Key = new RC4_KEY();
            RC4_set_key(ref rc4Key, keylen, key);
            return rc4Key;
        }

        internal static unsafe byte[] RC4EncryptOrDecrypt(RC4_KEY rc4Key, byte* input, int inputlen)
        {
            byte[] output = new byte[inputlen];
            fixed (byte* outPtr = output)
            {
                RC4(ref rc4Key, (ulong)inputlen, input, outPtr);
            }
            return output;
        }

        internal static unsafe byte[] EVPDigest(byte* key, int keylen, byte* input, int inputlen, out uint outputlen)
        {
            byte[] output = new byte[EVP_MAX_MD_SIZE];
            IntPtr ctx = EVP_MD_CTX_create();
            try
            {
                EVP_DigestInit_ex(ctx, EVP_md5(), IntPtr.Zero);
                EVP_DigestUpdate(ctx, key, (size_t)keylen);
                EVP_DigestUpdate(ctx, input, (size_t)inputlen);
                unsafe
                {
                    fixed (byte* outPtr = output)
                    {
                        EVP_DigestFinal_ex(ctx, outPtr, out outputlen);
                    }
                }
            }
            finally
            {
                EVP_MD_CTX_destroy(ctx);
            }
            return output;
        }

        internal static unsafe byte[] EVPEncryptOrDecrypt(int x, bool encrypt, byte* key, int keylen, byte* input, int inputlen)
        {
            if (x > 0)
            {
                EVP_CIPHER_CTX ctx = EVPAllocateContext(encrypt, key, keylen);
                try
                {
                    return EVPEncryptOrDecrypt(ctx, input, inputlen);
                }
                finally
                {
                    EVPFreeContext(ctx);
                }
            }
            else
            {
                byte[] output = new byte[inputlen];
                RC4_KEY k = new RC4_KEY();
                RC4_set_key(ref k, keylen, key);
                fixed (byte* outPtr = output)
                {
                    RC4(ref k, (ulong) inputlen, input, outPtr);
                }
                return output;
            }
        }

        internal static unsafe EVP_CIPHER_CTX EVPAllocateContext(bool encrypt, byte* key, int keylen)
        {
            EVP_CIPHER_CTX ctx = new EVP_CIPHER_CTX();
            EVP_CIPHER_CTX_init(ref ctx);
            try
            {
                EVP_CipherInit_ex(ref ctx, EVP_rc4(), IntPtr.Zero, key, IntPtr.Zero, encrypt ? 1 : 0);
            }
            catch
            {
                EVPFreeContext(ctx);
                throw;
            }
            return ctx;
        }

        internal static void EVPFreeContext(EVP_CIPHER_CTX ctx)
        {
            EVP_CIPHER_CTX_cleanup(ref ctx);
        }

        internal static unsafe byte[] EVPEncryptOrDecrypt(bool encrypt, byte* key, int keylen, byte* input, int inputlen)
        {
            EVP_CIPHER_CTX ctx = EVPAllocateContext(encrypt, key, keylen);
            try
            {
                return EVPEncryptOrDecrypt(ctx, input, inputlen);
            }
            finally
            {
                EVPFreeContext(ctx);
            }
        }

        internal static unsafe byte[] EVPEncryptOrDecrypt(EVP_CIPHER_CTX ctx, byte* input, int inputlen)
        {
            byte[] output = new byte[inputlen];

            fixed (byte* outPtr = output)
            {
                EVP_Cipher(ref ctx, outPtr, input, output.Length);
            }
            return output;
        }

        internal static unsafe byte[] HMACDigest(byte* key, int keylen, byte* input, int inputlen, byte* prefix, int prefixlen)
        {
            HMAC_CTX ctx = new HMAC_CTX();
            byte[] output = new byte[16];

            HMAC_CTX_init(ref ctx);
            try
            {
                HMAC_Init_ex(ref ctx, key, keylen, EVP_md5(), IntPtr.Zero);
                if (prefixlen > 0)
                {
                    HMAC_Update(ref ctx, prefix, prefixlen);
                }
                HMAC_Update(ref ctx, input, inputlen);
                fixed (byte* hashPtr = output)
                {
                    uint hashLength;
                    HMAC_Final(ref ctx, hashPtr, out hashLength);
                }
            }
            finally
            {
                HMAC_CTX_cleanup(ref ctx);
            }
            return output;
        }
    }
}
