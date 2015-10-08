// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;

using OM_uint32 = System.UInt32;

internal static partial class Interop
{
    internal static partial class Libraries
    {
        // TODO (Issue #3715): Figure out the correct library on OSX
        internal const string LibGssApi = "libgssapi_krb5.so.2";
    }

    internal static partial class libgssapi
    {
        [DllImport(Interop.Libraries.LibGssApi)]
        internal static extern OM_uint32 gss_release_buffer(
            out OM_uint32 minor_status,
            IntPtr buffer);

        [DllImport(Interop.Libraries.LibGssApi)]
        internal static extern OM_uint32 gss_display_status(
            out OM_uint32 minor_status,
            OM_uint32 status_value,
            int status_type,
            SafeGssHandle mech_type,
            ref OM_uint32 message_context,
            SafeGssBufferHandle status_string);

        [DllImport(Interop.Libraries.LibGssApi)]
        internal static extern OM_uint32 gss_import_name(
            out OM_uint32 minor_status,
            SafeGssBufferHandle input_name_buffer,
            ref gss_OID_desc input_name_type,
            ref IntPtr output_name);

        [DllImport(Interop.Libraries.LibGssApi)]
        internal static extern OM_uint32 gss_release_name(
            out OM_uint32 minor_status,
            ref IntPtr input_name);

        [DllImport(Interop.Libraries.LibGssApi)]
        internal static extern OM_uint32 gss_acquire_cred(
            out OM_uint32 minor_status,
            SafeGssNameHandle desired_name,
            OM_uint32 time_req,
            ref gss_OID_set_desc desired_mechs,
            int cred_usage,
            ref IntPtr output_cred_handle,
            SafeGssHandle actual_mechs,
            out OM_uint32 time_rec);

        [DllImport(Interop.Libraries.LibGssApi)]
        internal static extern OM_uint32 gss_acquire_cred_with_password(
            out OM_uint32 minor_status,
            SafeGssNameHandle desired_name,
            SafeGssBufferHandle password,
            OM_uint32 time_req,
            ref gss_OID_set_desc desired_mechs,
            int cred_usage,
            ref IntPtr output_cred_handle,
            SafeGssHandle actual_mechs,
            out OM_uint32 time_rec);

        [DllImport(Interop.Libraries.LibGssApi)]
        internal static extern OM_uint32 gss_release_cred(
            out OM_uint32 minor_status,
            ref IntPtr cred_handle);

        [DllImport(Interop.Libraries.LibGssApi)]
        internal static extern OM_uint32 gss_init_sec_context(
            out OM_uint32 minor_status,
            SafeGssCredHandle initiator_cred_handle,
            ref SafeGssContextHandle context_handle,
            SafeGssNameHandle target_name,
            ref gss_OID_desc mech_type,
            OM_uint32 req_flags,
            OM_uint32 time_req,
            SafeGssHandle input_chain_bindings,
            SafeGssBufferHandle input_token,
            SafeGssHandle actual_mech_type,
            SafeGssBufferHandle output_token,
            out OM_uint32 ret_flags,
            out OM_uint32 time_rec);

        [DllImport(Interop.Libraries.LibGssApi)]
        internal static extern OM_uint32 gss_accept_sec_context(
            out OM_uint32 minor_status,
            ref SafeGssContextHandle context_handle,
            SafeGssCredHandle initiator_cred_handle,
            SafeGssBufferHandle input_token,
            SafeGssHandle input_chan_bindings,
            SafeGssHandle src_name,
            SafeGssHandle mech_type,
            SafeGssBufferHandle output_token,
            out OM_uint32 ret_flags,
            out OM_uint32 time_rec,
            SafeGssHandle delegated_cred_handle);

        [DllImport(Interop.Libraries.LibGssApi)]
        internal static extern OM_uint32 gss_delete_sec_context(
            out OM_uint32 minor_status,
            ref IntPtr context_handle,
            SafeGssBufferHandle buffer);

        [DllImport(Interop.Libraries.LibGssApi)]
        internal static extern OM_uint32 gss_wrap(
            out OM_uint32 minor_status,
            SafeGssContextHandle context_handle,
            int conf_req_flag,
            OM_uint32 qop_req,
            SafeGssBufferHandle input_message_buffer,
            out int conf_state,
            SafeGssBufferHandle output_message_buffer);

        [DllImport(Interop.Libraries.LibGssApi)]
        internal static extern OM_uint32 gss_unwrap(
            out OM_uint32 minor_status,
            SafeGssContextHandle context_handle,
            SafeGssBufferHandle input_message_buffer,
            SafeGssBufferHandle output_message_buffer,
            out int conf_state,
            out OM_uint32 qop_state);

        [DllImport(Interop.Libraries.LibGssApi)]
        internal static extern OM_uint32 gss_inquire_context(
            out OM_uint32 minor_status,
            SafeGssContextHandle context_handle,
            out SafeGssNameHandle src_name,
            SafeGssHandle targ_name,
            out OM_uint32 lifetime_rec,
            SafeGssHandle mech_type,
            out OM_uint32 ctx_flags,
            out int locally_initiated,
            out int open_context);

        [DllImport(Interop.Libraries.LibGssApi)]
        internal static extern OM_uint32 gss_display_name(
            out OM_uint32 minor_status,
            SafeGssNameHandle input_name,
            SafeGssBufferHandle output_name_buffer,
            SafeGssHandle output_name_type);
    }
}
