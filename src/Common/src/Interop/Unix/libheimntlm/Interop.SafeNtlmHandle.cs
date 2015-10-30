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
        /// <summary>
        /// Wrapper around a ntlm_buf*
        /// </summary>
        internal sealed class SafeNtlmBufferHandle : SafeHandle
        {
            private readonly bool _isOutputBuffer;
            private readonly GCHandle _gch;
            private readonly GCHandle _arrayGcHandle = new GCHandle();

            // Return the buffer size
            public size_t Length
            {
                get
                {
                    if (IsInvalid)
                    {
                        return (size_t)0;
                    }
                    return ((ntlm_buf)_gch.Target).length;
                }
            }

            // Return a pointer to where data resides
            public IntPtr Value
            {
                get
                {
                    if (IsInvalid)
                    {
                        return IntPtr.Zero;
                    }
                    return ((ntlm_buf)_gch.Target).data;
                }
            }

            public SafeNtlmBufferHandle()
                : this(0, IntPtr.Zero)
            {
                _isOutputBuffer = true;
            }

            public SafeNtlmBufferHandle(byte[] data) : this(data, 0, (data == null) ? 0 : data.Length)
            {
            }

            public SafeNtlmBufferHandle(byte[] data, int offset, int count) : this(count, IntPtr.Zero)
            {
                if (data != null)
                {
                    _arrayGcHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
                    IntPtr address = new IntPtr(_arrayGcHandle.AddrOfPinnedObject().ToInt64() + offset);
                    Marshal.WriteIntPtr(handle, (int) Marshal.OffsetOf<ntlm_buf>("data"), address);
                }
            }

            public SafeNtlmBufferHandle(int length, IntPtr value)
                : base(IntPtr.Zero, true)
            {
                ntlm_buf buffer = new ntlm_buf
                    {
                        length = (size_t)length,
                        data = value,
                    };
                _gch = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                handle = _gch.AddrOfPinnedObject();
            }

            public override bool IsInvalid
            {
                get { return handle == IntPtr.Zero; }
            }

            public ntlm_buf ToBuffer()
            {
                return (ntlm_buf) _gch.Target;
            }

            // Note that _value should never be freed directly. For input
            // buffer, it is owned by the caller and for output buffer,
            // it is a by-product of some other allocation
            protected override bool ReleaseHandle()
            {
                ntlm_buf buffer = (ntlm_buf)_gch.Target;
                if (_isOutputBuffer && (buffer.data != IntPtr.Zero))
                {
                    if (_arrayGcHandle.IsAllocated)
                    {
                        _arrayGcHandle.Free();
                    }
                    else
                    {
                        heim_ntlm_free_buf(ref buffer);
                    }
                    buffer.data = IntPtr.Zero;
                }
                _gch.Free();
                SetHandle(IntPtr.Zero);
                return true;
            }
        }

        /// <summary>
        /// Wrapper around a session key used for signing
        /// </summary>
        internal sealed class SafeNtlmKeyHandle : SafeHandle
        {
            private GCHandle _gch;
            private uint _keyLength;
            private uint _sequenceNumber;
            private bool _isSealingKey;
            private readonly EVP_CIPHER_CTX _cipherContext;

            // From MS_NLMP SIGNKEY at https://msdn.microsoft.com/en-us/library/cc236711.aspx
            private const string s_keyMagic = "session key to {0}-to-{1} {2} key magic constant\0";
            private const string s_client = "client";
            private const string s_server = "server";
            private const string s_signing = "signing";
            private const string s_sealing = "sealing";

            public SafeNtlmKeyHandle(SafeNtlmBufferHandle key, bool isClient, bool sign)
                : base(IntPtr.Zero, true)
            {
                string keyMagic = string.Format(s_keyMagic, isClient ? s_client : s_server,
                    isClient ? s_server : s_client, sign ? s_signing : s_sealing);
                unsafe
                {
                    byte[] magic = Encoding.UTF8.GetBytes(keyMagic);
                    fixed (byte* magicPtr = magic)
                    {
                        byte[] digest = EVPDigest((byte*) key.Value.ToPointer(), (int) key.Length, magicPtr,
                            magic.Length, out _keyLength);
                        _isSealingKey = !sign;
                        if (_isSealingKey)
                        {
                            fixed (byte* digestPtr = digest)
                            {
                                _cipherContext = EVPAllocateContext(true, digestPtr, digest.Length);
                            }
                        }
                        _gch = GCHandle.Alloc(digest, GCHandleType.Pinned);
                        handle = _gch.AddrOfPinnedObject();
                    }
                }
            }

            public override bool IsInvalid
            {
                get { return handle == IntPtr.Zero; }
            }

            protected override bool ReleaseHandle()
            {
                if (_isSealingKey)
                {
                    EVPFreeContext(_cipherContext);
                }
                _gch.Free();
                SetHandle(IntPtr.Zero);
                return true;
            }

            public byte[] Sign(SafeNtlmKeyHandle sealingKey, byte[] buffer, int offset, int count)
            {
                Debug.Assert(!_isSealingKey, "Cannot sign with sealing key");
                byte[] output = new byte[16];
                Array.Clear(output, 0, output.Length);
                byte[] hash;
                unsafe
                {
                    fixed (byte* outPtr = output)
                    fixed (byte* bytePtr = buffer)
                    {
                        MarshalUint(outPtr, 0x00000001); // version
                        MarshalUint(outPtr + 12, _sequenceNumber);
                        hash = HMACDigest((byte*)handle.ToPointer(), (int)_keyLength, (bytePtr + offset), count,
                            outPtr + 12, 4);
                        _sequenceNumber++;
                    }
                }
                if ((sealingKey == null) || sealingKey.IsInvalid)
                {
                    Array.Copy(hash, 0, output, 4, 8);
                }
                else
                {
                    byte[] cipher = sealingKey.SealOrUnseal(true, hash, 0, 8);
                    Array.Copy(cipher, 0, output, 4, cipher.Length);
                }
                return output;
            }

            public byte[] SealOrUnseal(bool seal, byte[] buffer, int offset, int count)
            {
                Debug.Assert(_isSealingKey, "Cannot seal or unseal with signing key");
                unsafe
                {
                    fixed (byte* bytePtr = buffer)
                    {
                        // Since RC4 is XOR-based, encrypt or decrypt is relative to input data
                        return EVPEncryptOrDecrypt(_cipherContext, (bytePtr + offset), count);
                    }
                }
            }

#if DEBUG
            public void Dump(string message)
            {
                MockUtils.MockLogging.Dump(null, "SafeNtlmBufferHandle.Dump", message, handle, (int) _keyLength);
            }
#endif

            private static unsafe void MarshalUint(byte* ptr, uint num)
            {
                for (int i = 0; i < 4; i++)
                {
                    ptr[i] = (byte)(num & 0xff);
                    num >>= 8;
                }
            }
        }

        /// <summary>
        /// Wrapper around a ntlm_type3*
        /// </summary>
        internal sealed class SafeNtlmType3Handle : SafeHandle
        {
            // heim_ntlm_encode_type3 requires a valid pointer for this
            private static readonly IntPtr s_workstationPtr = Marshal.StringToHGlobalAnsi(string.Empty);

            private GCHandle _gch;

            public SafeNtlmType3Handle(SafeNtlmBufferHandle type2Data) : base(IntPtr.Zero, true)
            {
                ntlm_type2 message = new ntlm_type2();
                int status = heim_ntlm_decode_type2(type2Data, ref message);
                HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_decode_type2 failed", status);

                _gch = GCHandle.Alloc(message, GCHandleType.Pinned);
                handle = _gch.AddrOfPinnedObject();
            }

            public override bool IsInvalid
            {
                get { return handle == IntPtr.Zero; }
            }

            public SafeNtlmBufferHandle GetResponse(uint flags, string username, string password, string domain, out SafeNtlmBufferHandle sessionKey)
            {
                SafeNtlmBufferHandle outputData = new SafeNtlmBufferHandle();
                sessionKey = null;
                ntlm_type2 type2Message = (ntlm_type2)_gch.Target;

                using (SafeNtlmBufferHandle key = new SafeNtlmBufferHandle())
                using (SafeNtlmBufferHandle lmResponse = new SafeNtlmBufferHandle())
                using (SafeNtlmBufferHandle ntResponse = new SafeNtlmBufferHandle())
                {
                    int status = heim_ntlm_nt_key(password, key);
                    HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_nt_key failed", status);

                    byte[] baseSessionKey = new byte[16];
                    unsafe
                    {
                        byte* challenge = type2Message.challenge;
                        fixed (byte* sessionKeyPtr = baseSessionKey)
                        {
                            status = heim_ntlm_calculate_lm2(key.Value, key.Length, username, domain, challenge,
                                sessionKeyPtr, lmResponse);
                            HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_calculate_lm2 failed", status);
                        }
                        if (type2Message.targetinfo.length == (size_t)0)
                        {
                            status = heim_ntlm_calculate_ntlm1(key.Value, key.Length, challenge, ntResponse);
                            HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_calculate_ntlm1 failed", status);
                        }
                        else
                        {
                            using (
                                SafeNtlmBufferHandle targetInfo =
                                    new SafeNtlmBufferHandle((int)type2Message.targetinfo.length,
                                        type2Message.targetinfo.data))
                            {
                                fixed (byte* sessionKeyPtr = baseSessionKey)
                                {
                                    status = heim_ntlm_calculate_ntlm2(key.Value, key.Length, username,
                                        domain,
                                        challenge,
                                        targetInfo, sessionKeyPtr, ntResponse);
                                    HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_calculate_ntlm2 failed",
                                        status);
                                }
                            }
                        }
                    }

                    ntlm_type3 type3Message = new ntlm_type3();
                    type3Message.flags = flags;
                    SafeNtlmBufferHandle masterKey = null;
                    try
                    {
                        type3Message.username = Marshal.StringToHGlobalAnsi(username);
                        type3Message.targetname = Marshal.StringToHGlobalAnsi(domain);
                        type3Message.lm = lmResponse.ToBuffer();
                        type3Message.ntlm = ntResponse.ToBuffer();
                        type3Message.ws = s_workstationPtr;
                        sessionKey = new SafeNtlmBufferHandle();    // Should not Dispose on success

                        if (type2Message.targetinfo.length == (size_t) 0)
                        {
                            masterKey = new SafeNtlmBufferHandle();
                            unsafe
                            {
                                status = heim_ntlm_build_ntlm1_master((byte*) key.Value.ToPointer(),
                                    key.Length, sessionKey, masterKey);
                            }
                            HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_build_ntlm1_master failed", status);
                        }
                        else
                        {
                            // Only first 16 bytes of the NTLMv2 response should be passed
                            using (
                                SafeNtlmBufferHandle blob = new SafeNtlmBufferHandle(16,
                                    ntResponse.Value))
                            {
                                unsafe
                                {
                                    fixed (byte* sessionKeyPtr = baseSessionKey)
                                    {
                                        heim_ntlm_build_ntlm2_master(sessionKeyPtr,
                                            (size_t) baseSessionKey.Length, blob, sessionKey, out masterKey);
                                    }
                                }
                            }
                        }
                        type3Message.session_key = masterKey.ToBuffer();

                        size_t micOffset = (size_t) 0;
                        status = heim_ntlm_encode_type3(ref type3Message, outputData, ref micOffset);
                        HeimdalNtlmException.AssertOrThrowIfError("heim_ntlm_encode_type3 failed", status);
                    }
                    catch
                    {
                        if ((sessionKey != null) && !sessionKey.IsInvalid)
                        {
                            sessionKey.Dispose();
                            sessionKey = null;
                        }
                        throw;
                    }
                    finally
                    {
                        if (type3Message.username != IntPtr.Zero)
                        {
                            Marshal.FreeHGlobal(type3Message.username);
                        }
                        if (type3Message.targetname != IntPtr.Zero)
                        {
                            Marshal.FreeHGlobal(type3Message.targetname);
                        }
                        if ((masterKey != null) && !masterKey.IsInvalid)
                        {
                            masterKey.Dispose();
                        }
                    }
                }

                return outputData;
            }

            protected override bool ReleaseHandle()
            {
                heim_ntlm_free_type2(handle);
                _gch.Free();
                SetHandle(IntPtr.Zero);
                return true;
            }
        }
    }
}
