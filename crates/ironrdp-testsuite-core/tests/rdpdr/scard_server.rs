//! Server side of smart card redirection: the calls a server encodes, the returns it decodes, and
//! the `RdpdrServer` pieces it needs (capabilities, completion ids, raw output buffers).
//!
//! Calls are checked against the client-side decoders and against byte layouts produced by
//! FreeRDP's `smartcard_pack_*_call`; returns against the client-side encoders.

use ironrdp_core::{ReadCursor, encode_vec};
use ironrdp_pdu::utils::CharacterSet;
use ironrdp_rdpdr::pdu::RdpdrPdu;
use ironrdp_rdpdr::pdu::efs::{
    CapabilityMessage, ClientNameRequest, ClientNameRequestUnicodeFlag, CoreCapabilityKind, DeviceControlResponse,
    DeviceIoResponse, NtStatus, VERSION_MINOR_RDP51, VersionAndIdPdu, VersionAndIdPduKind,
};
use ironrdp_rdpdr::pdu::esc::{
    CardProtocol, CardState, CardStateFlags, ConnectCall, ConnectCommon, ConnectReturn, ContextCall, ControlCall,
    ControlReturn, EstablishContextCall, EstablishContextReturn, GetAttribCall, GetAttribReturn, GetStatusChangeCall,
    GetStatusChangeReturn, GetTransmitCountCall, HCardAndDispositionCall, ListReadersCall, ListReadersReturn,
    LongReturn, ReaderState, ReaderStateCommonCall, ReconnectCall, ReconnectReturn, ReturnCode, SCardIORequest,
    ScardCall, ScardContext, ScardHandle, ScardIoCtlCode, ScardReturn, Scope, SetAttribCall, StateCall, StateReturn,
    StatusCall, StatusReturn, TransmitCall, TransmitReturn,
};
use ironrdp_rdpdr::server::{NoopRdpdrServerBackend, RdpdrServer, RdpdrServerMessage};
use ironrdp_svc::SvcProcessor as _;

use super::{completion_id_of, handshake_to_active, read_u32};

fn context() -> ScardContext {
    ScardContext::new(0x0102_0304)
}

fn handle() -> ScardHandle {
    ScardHandle::new(context(), 0x0A0B_0C0D)
}

/// Encodes `call` as the server does, then decodes it as the client does.
fn call_round_trip(io_ctl_code: ScardIoCtlCode, call: &ScardCall) -> ScardCall {
    let encoded = call.encode(io_ctl_code).unwrap();
    assert_eq!(encoded.len() % 8, 0, "RPCE messages are padded to 8 bytes");
    ScardCall::decode(io_ctl_code, &mut ReadCursor::new(&encoded)).unwrap()
}

/// Wraps an NDR body the way FreeRDP's `smartcard_pack_*_call` output is framed: the common and
/// private type headers, then the body padded to 8 bytes.
fn rpce_frame(body: &[u8]) -> Vec<u8> {
    let padded_len = body.len().next_multiple_of(8);
    let mut pdu = vec![0x01, 0x10, 0x08, 0x00, 0xCC, 0xCC, 0xCC, 0xCC];
    // ObjectBufferLength: the body with its padding
    pdu.extend_from_slice(&u32::try_from(padded_len).unwrap().to_le_bytes());
    pdu.extend_from_slice(&0u32.to_le_bytes());
    pdu.extend_from_slice(body);
    pdu.resize(16 + padded_len, 0);
    pdu
}

fn u32s(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

#[test]
fn scard_calls_round_trip_through_the_client_decoders() {
    let state = |reader: &str, current: CardStateFlags| ReaderState {
        reader: reader.to_owned(),
        common: ReaderStateCommonCall {
            current_state: current,
            event_state: CardStateFlags::SCARD_STATE_UNAWARE,
            atr_length: 3,
            atr: {
                let mut atr = [0; 36];
                atr[..3].copy_from_slice(&[0x3B, 0x8F, 0x80]);
                atr
            },
        },
    };

    let calls = [
        (
            ScardIoCtlCode::EstablishContext,
            ScardCall::EstablishContextCall(EstablishContextCall { scope: Scope::System }),
        ),
        (
            ScardIoCtlCode::ReleaseContext,
            ScardCall::ContextCall(ContextCall { context: context() }),
        ),
        (
            ScardIoCtlCode::Cancel,
            ScardCall::ContextCall(ContextCall { context: context() }),
        ),
        (
            ScardIoCtlCode::GetStatusChangeW,
            ScardCall::GetStatusChangeCall(GetStatusChangeCall {
                context: context(),
                timeout: 0xFFFF_FFFF,
                states_ptr_length: 2,
                states_ptr: 0x0002_0004,
                states_length: 2,
                states: vec![
                    state("Yubico YubiKey 00 00", CardStateFlags::SCARD_STATE_EMPTY),
                    state("\\\\?PnP?\\Notification", CardStateFlags::SCARD_STATE_UNAWARE),
                ],
            }),
        ),
        (
            ScardIoCtlCode::GetStatusChangeA,
            ScardCall::GetStatusChangeCall(GetStatusChangeCall {
                context: context(),
                timeout: 1000,
                states_ptr_length: 1,
                states_ptr: 0x0002_0004,
                states_length: 1,
                // 7 bytes with the NUL: its referent is padded
                states: vec![state("Reader", CardStateFlags::SCARD_STATE_PRESENT)],
            }),
        ),
        (
            ScardIoCtlCode::ConnectW,
            ScardCall::ConnectCall(ConnectCall {
                reader: "Yubico YubiKey 00 00".to_owned(),
                common: ConnectCommon {
                    context: context(),
                    share_mode: 2,
                    preferred_protocols: CardProtocol::SCARD_PROTOCOL_TX,
                },
            }),
        ),
        (
            ScardIoCtlCode::ConnectA,
            ScardCall::ConnectCall(ConnectCall {
                reader: "Reader".to_owned(),
                common: ConnectCommon {
                    context: context(),
                    share_mode: 1,
                    preferred_protocols: CardProtocol::SCARD_PROTOCOL_T1,
                },
            }),
        ),
        (
            ScardIoCtlCode::Reconnect,
            ScardCall::ReconnectCall(ReconnectCall {
                handle: handle(),
                share_mode: 2,
                preferred_protocols: CardProtocol::SCARD_PROTOCOL_T0,
                initialization: 1,
            }),
        ),
        (
            ScardIoCtlCode::Disconnect,
            ScardCall::HCardAndDispositionCall(HCardAndDispositionCall {
                handle: handle(),
                disposition: 1,
            }),
        ),
        (
            ScardIoCtlCode::BeginTransaction,
            ScardCall::HCardAndDispositionCall(HCardAndDispositionCall {
                handle: handle(),
                disposition: 0,
            }),
        ),
        (
            ScardIoCtlCode::Transmit,
            ScardCall::TransmitCall(TransmitCall {
                handle: handle(),
                send_pci: SCardIORequest {
                    protocol: CardProtocol::SCARD_PROTOCOL_T1,
                    extra_bytes_length: 0,
                    extra_bytes: Vec::new(),
                },
                send_length: 5,
                send_buffer: vec![0x00, 0xA4, 0x04, 0x00, 0x00],
                recv_pci: None,
                recv_buffer_is_null: false,
                recv_length: 258,
            }),
        ),
        (
            // extra bytes on both PCIs, and an odd send buffer followed by the receive PCI
            ScardIoCtlCode::Transmit,
            ScardCall::TransmitCall(TransmitCall {
                handle: handle(),
                send_pci: SCardIORequest {
                    protocol: CardProtocol::SCARD_PROTOCOL_T1,
                    extra_bytes_length: 2,
                    extra_bytes: vec![0xEE, 0xFF],
                },
                send_length: 3,
                send_buffer: vec![0x00, 0xCA, 0x01],
                recv_pci: Some(SCardIORequest {
                    protocol: CardProtocol::SCARD_PROTOCOL_T1,
                    extra_bytes_length: 3,
                    extra_bytes: vec![1, 2, 3],
                }),
                recv_buffer_is_null: false,
                recv_length: 64,
            }),
        ),
        (
            ScardIoCtlCode::StatusW,
            ScardCall::StatusCall(StatusCall {
                handle: handle(),
                reader_names_is_null: false,
                reader_length: 0xFFFF_FFFF,
                atr_length: 32,
            }),
        ),
        (
            ScardIoCtlCode::State,
            ScardCall::StateCall(StateCall {
                handle: handle(),
                atr_is_null: false,
                atr_length: 36,
            }),
        ),
        (
            ScardIoCtlCode::Control,
            ScardCall::ControlCall(ControlCall {
                handle: handle(),
                control_code: 0x0031_3520,
                in_buffer: vec![1, 2, 3],
                out_buffer_is_null: false,
                out_buffer_size: 2048,
            }),
        ),
        (
            ScardIoCtlCode::Control,
            ScardCall::ControlCall(ControlCall {
                handle: handle(),
                control_code: 0x0031_3520,
                in_buffer: Vec::new(),
                out_buffer_is_null: true,
                out_buffer_size: 0,
            }),
        ),
        (
            ScardIoCtlCode::GetAttrib,
            ScardCall::GetAttribCall(GetAttribCall {
                handle: handle(),
                attr_id: 0x0009_0303,
                attr_is_null: false,
                attr_length: 33,
            }),
        ),
        (
            ScardIoCtlCode::SetAttrib,
            ScardCall::SetAttribCall(SetAttribCall {
                handle: handle(),
                attr_id: 0x0007_A007,
                attr: vec![9, 8],
            }),
        ),
        (
            ScardIoCtlCode::GetTransmitCount,
            ScardCall::GetTransmitCountCall(GetTransmitCountCall { handle: handle() }),
        ),
    ];

    for (io_ctl_code, call) in calls {
        assert_eq!(call_round_trip(io_ctl_code, &call), call, "{io_ctl_code:?}");
    }
}

#[test]
fn scard_list_readers_call_round_trips_with_and_without_groups() {
    for (io_ctl_code, charset) in [
        (ScardIoCtlCode::ListReadersW, CharacterSet::Unicode),
        (ScardIoCtlCode::ListReadersA, CharacterSet::Ansi),
    ] {
        let groups = vec!["SCard$DefaultReaders".to_owned()];
        let c_bytes = u32::try_from(ironrdp_pdu::utils::encoded_multistring_len(&groups, charset)).unwrap();
        let call = ListReadersCall {
            context: context(),
            groups_ptr_length: c_bytes,
            groups_length: c_bytes,
            groups_ptr: 0x0002_0004,
            groups,
            readers_is_null: true,
            readers_size: 0xFFFF_FFFF,
        };
        let call = ScardCall::ListReadersCall(call);
        assert_eq!(call_round_trip(io_ctl_code, &call), call);

        let no_groups = ScardCall::ListReadersCall(ListReadersCall {
            context: context(),
            groups_ptr_length: 0,
            groups_length: 0,
            groups_ptr: 0,
            groups: Vec::new(),
            readers_is_null: false,
            readers_size: 512,
        });
        assert_eq!(call_round_trip(io_ctl_code, &no_groups), no_groups);
    }
}

// oracle: FreeRDP smartcard_pack_connect_w_call
#[test]
fn scard_connect_w_call_matches_freerdp_layout() {
    let call = ScardCall::ConnectCall(ConnectCall {
        reader: "R".to_owned(),
        common: ConnectCommon {
            context: context(),
            share_mode: 2,
            preferred_protocols: CardProtocol::SCARD_PROTOCOL_TX,
        },
    });

    let mut body = u32s(&[0x0002_0000, 4, 0x0002_0004, 2, 3]); // szReader, hContext, share, protocols
    body.extend(u32s(&[2, 0, 2])); // conformant varying string header
    body.extend([b'R', 0, 0, 0]); // "R\0" in UTF-16
    body.extend(u32s(&[4])); // hContext referent
    body.extend(0x0102_0304u32.to_le_bytes());

    assert_eq!(call.encode(ScardIoCtlCode::ConnectW).unwrap(), rpce_frame(&body));
}

// oracle: FreeRDP smartcard_pack_transmit_call
#[test]
fn scard_transmit_call_matches_freerdp_layout() {
    let call = ScardCall::TransmitCall(TransmitCall {
        handle: handle(),
        send_pci: SCardIORequest {
            protocol: CardProtocol::SCARD_PROTOCOL_T1,
            extra_bytes_length: 0,
            extra_bytes: Vec::new(),
        },
        send_length: 3,
        send_buffer: vec![0x00, 0xA4, 0x04],
        recv_pci: None,
        recv_buffer_is_null: false,
        recv_length: 258,
    });

    let mut body = u32s(&[
        4,
        0x0002_0000, // hContext
        4,
        0x0002_0004, // hCard
        2,
        0,
        0, // ioSendPci: dwProtocol, cbExtraBytes, NULL pbExtraBytes
        3,
        0x0002_0008, // cbSendLength, pbSendBuffer
        0,           // NULL pioRecvPci
        0,
        258, // fpbRecvBufferIsNULL, cbRecvLength
        4,
        0x0102_0304, // hContext referent
        4,
        0x0A0B_0C0D, // hCard referent
        3,           // pbSendBuffer referent
    ]);
    body.extend([0x00, 0xA4, 0x04, 0x00]); // the send buffer and its padding

    assert_eq!(call.encode(ScardIoCtlCode::Transmit).unwrap(), rpce_frame(&body));
}

// oracle: FreeRDP smartcard_pack_get_status_change_w_call / smartcard_pack_reader_state_w
#[test]
fn scard_get_status_change_w_call_matches_freerdp_layout() {
    let call = ScardCall::GetStatusChangeCall(GetStatusChangeCall {
        context: context(),
        timeout: 500,
        states_ptr_length: 1,
        states_ptr: 0x0002_0004,
        states_length: 1,
        states: vec![ReaderState {
            reader: "AB".to_owned(),
            common: ReaderStateCommonCall {
                current_state: CardStateFlags::SCARD_STATE_EMPTY,
                event_state: CardStateFlags::SCARD_STATE_UNAWARE,
                atr_length: 0,
                atr: [0; 36],
            },
        }],
    });

    let mut body = u32s(&[4, 0x0002_0000, 500, 1, 0x0002_0004, 4, 0x0102_0304]);
    body.extend(u32s(&[1, 0x0002_0008, 0x10, 0, 0])); // cReaders, szReader, states, cbAtr
    body.extend([0; 36]); // rgbAtr
    body.extend(u32s(&[3, 0, 3])); // "AB\0": 3 UTF-16 code units
    body.extend([b'A', 0, b'B', 0, 0, 0, 0, 0]); // the string and its padding

    assert_eq!(
        call.encode(ScardIoCtlCode::GetStatusChangeW).unwrap(),
        rpce_frame(&body)
    );
}

#[test]
fn scard_call_encode_rejects_mismatched_or_unsupported_io_ctl_codes() {
    let connect = ScardCall::ConnectCall(ConnectCall {
        reader: "R".to_owned(),
        common: ConnectCommon {
            context: context(),
            share_mode: 2,
            preferred_protocols: CardProtocol::SCARD_PROTOCOL_T1,
        },
    });
    assert!(connect.encode(ScardIoCtlCode::Transmit).is_err());
    assert!(ScardCall::Unsupported.encode(ScardIoCtlCode::ReadCacheW).is_err());
}

/// Encodes `ret` as the client does, then decodes it as the server does.
fn return_round_trip(io_ctl_code: ScardIoCtlCode, ret: &dyn ironrdp_core::Encode) -> ScardReturn {
    let encoded = encode_vec(ret).unwrap();
    ScardReturn::decode(io_ctl_code, &mut ReadCursor::new(&encoded)).unwrap()
}

#[test]
fn scard_returns_round_trip_through_the_client_encoders() {
    let reader_state = ReaderStateCommonCall {
        current_state: CardStateFlags::SCARD_STATE_EMPTY,
        event_state: CardStateFlags::SCARD_STATE_PRESENT | CardStateFlags::SCARD_STATE_CHANGED,
        atr_length: 2,
        atr: {
            let mut atr = [0; 36];
            atr[..2].copy_from_slice(&[0x3B, 0x00]);
            atr
        },
    };
    let mut atr = [0; 32];
    atr[..4].copy_from_slice(&[0x3B, 0x8F, 0x80, 0x01]);
    let pci = SCardIORequest {
        protocol: CardProtocol::SCARD_PROTOCOL_T1,
        extra_bytes_length: 1,
        extra_bytes: vec![7],
    };

    let checks: Vec<(ScardIoCtlCode, Box<dyn ironrdp_core::Encode>, ScardReturn)> = vec![
        (
            ScardIoCtlCode::Disconnect,
            Box::new(LongReturn::new(ReturnCode::Success)),
            ScardReturn::Long(LongReturn::new(ReturnCode::Success).into_inner()),
        ),
        (
            ScardIoCtlCode::EstablishContext,
            Box::new(EstablishContextReturn::new(ReturnCode::Success, context())),
            ScardReturn::EstablishContext(EstablishContextReturn::new(ReturnCode::Success, context()).into_inner()),
        ),
        (
            ScardIoCtlCode::ListReadersW,
            Box::new(ListReadersReturn::new(
                ReturnCode::Success,
                vec!["A".to_owned(), "Yubico".to_owned()],
                CharacterSet::Unicode,
            )),
            ScardReturn::ListReaders(
                ListReadersReturn::new(
                    ReturnCode::Success,
                    vec!["A".to_owned(), "Yubico".to_owned()],
                    CharacterSet::Unicode,
                )
                .into_inner(),
            ),
        ),
        (
            ScardIoCtlCode::ListReadersA,
            Box::new(ListReadersReturn::probe(ReturnCode::Success, 20, CharacterSet::Ansi)),
            ScardReturn::ListReaders(
                ListReadersReturn::probe(ReturnCode::Success, 20, CharacterSet::Ansi).into_inner(),
            ),
        ),
        (
            ScardIoCtlCode::GetStatusChangeW,
            Box::new(GetStatusChangeReturn::new(
                ReturnCode::Success,
                vec![reader_state.clone(), reader_state.clone()],
            )),
            ScardReturn::GetStatusChange(
                GetStatusChangeReturn::new(ReturnCode::Success, vec![reader_state.clone(), reader_state]).into_inner(),
            ),
        ),
        (
            ScardIoCtlCode::ConnectW,
            Box::new(ConnectReturn::new(
                ReturnCode::Success,
                handle(),
                CardProtocol::SCARD_PROTOCOL_T1,
            )),
            ScardReturn::Connect(
                ConnectReturn::new(ReturnCode::Success, handle(), CardProtocol::SCARD_PROTOCOL_T1).into_inner(),
            ),
        ),
        (
            ScardIoCtlCode::Reconnect,
            Box::new(ReconnectReturn::new(
                ReturnCode::Success,
                CardProtocol::SCARD_PROTOCOL_T0,
            )),
            ScardReturn::Reconnect(
                ReconnectReturn::new(ReturnCode::Success, CardProtocol::SCARD_PROTOCOL_T0).into_inner(),
            ),
        ),
        (
            ScardIoCtlCode::Transmit,
            Box::new(TransmitReturn::new(ReturnCode::Success, None, vec![0x90, 0x00])),
            ScardReturn::Transmit(TransmitReturn::new(ReturnCode::Success, None, vec![0x90, 0x00]).into_inner()),
        ),
        (
            ScardIoCtlCode::Transmit,
            Box::new(TransmitReturn::new(
                ReturnCode::Success,
                Some(pci.clone()),
                vec![0x6A, 0x82, 0x01],
            )),
            ScardReturn::Transmit(
                TransmitReturn::new(ReturnCode::Success, Some(pci), vec![0x6A, 0x82, 0x01]).into_inner(),
            ),
        ),
        (
            ScardIoCtlCode::Transmit,
            Box::new(TransmitReturn::recv_probe(ReturnCode::Success, None, 256)),
            ScardReturn::Transmit(TransmitReturn::recv_probe(ReturnCode::Success, None, 256).into_inner()),
        ),
        (
            ScardIoCtlCode::StatusW,
            Box::new(StatusReturn::new(
                ReturnCode::Success,
                vec!["Yubico".to_owned()],
                CardState::SpecificMode,
                CardProtocol::SCARD_PROTOCOL_T1,
                atr,
                4,
                CharacterSet::Unicode,
            )),
            ScardReturn::Status(
                StatusReturn::new(
                    ReturnCode::Success,
                    vec!["Yubico".to_owned()],
                    CardState::SpecificMode,
                    CardProtocol::SCARD_PROTOCOL_T1,
                    atr,
                    4,
                    CharacterSet::Unicode,
                )
                .into_inner(),
            ),
        ),
        (
            ScardIoCtlCode::State,
            Box::new(StateReturn::new(
                ReturnCode::Success,
                CardState::Present,
                CardProtocol::SCARD_PROTOCOL_T0,
                vec![0x3B, 0x00, 0x01],
            )),
            ScardReturn::State(
                StateReturn::new(
                    ReturnCode::Success,
                    CardState::Present,
                    CardProtocol::SCARD_PROTOCOL_T0,
                    vec![0x3B, 0x00, 0x01],
                )
                .into_inner(),
            ),
        ),
        (
            ScardIoCtlCode::Control,
            Box::new(ControlReturn::new(ReturnCode::Success, vec![1, 2, 3, 4, 5])),
            ScardReturn::Control(ControlReturn::new(ReturnCode::Success, vec![1, 2, 3, 4, 5]).into_inner()),
        ),
        (
            ScardIoCtlCode::GetAttrib,
            Box::new(GetAttribReturn::attr_probe(ReturnCode::Success, 33)),
            ScardReturn::GetAttrib(GetAttribReturn::attr_probe(ReturnCode::Success, 33).into_inner()),
        ),
        (
            ScardIoCtlCode::GetAttrib,
            Box::new(GetAttribReturn::new(ReturnCode::Success, vec![0x3B; 9])),
            ScardReturn::GetAttrib(GetAttribReturn::new(ReturnCode::Success, vec![0x3B; 9]).into_inner()),
        ),
    ];

    for (io_ctl_code, encoded, expected) in checks {
        let decoded = return_round_trip(io_ctl_code, encoded.as_ref());
        assert_eq!(decoded, expected, "{io_ctl_code:?}");
        assert_eq!(decoded.return_code(), ReturnCode::Success);
    }
}

#[test]
fn scard_get_status_change_timeout_keeps_the_reader_states() {
    let state = ReaderStateCommonCall {
        current_state: CardStateFlags::SCARD_STATE_EMPTY,
        event_state: CardStateFlags::SCARD_STATE_EMPTY,
        atr_length: 0,
        atr: [0; 36],
    };
    let decoded = return_round_trip(
        ScardIoCtlCode::GetStatusChangeA,
        &GetStatusChangeReturn::new(ReturnCode::Timeout, vec![state.clone()]),
    );
    assert_eq!(
        decoded,
        ScardReturn::GetStatusChange(GetStatusChangeReturn::new(ReturnCode::Timeout, vec![state]).into_inner())
    );
}

#[test]
fn scard_failed_returns_decode_without_a_body() {
    // FreeRDP's smartcard_pack_*_return stop after the return code on failure.
    let no_smartcard = rpce_frame(&u32s(&[0x8010_000C]));
    let decoded = ScardReturn::decode(ScardIoCtlCode::ConnectW, &mut ReadCursor::new(&no_smartcard)).unwrap();
    assert_eq!(
        decoded,
        ScardReturn::Connect(
            ConnectReturn::new(
                ReturnCode::NoSmartcard,
                ScardHandle::empty(),
                CardProtocol::SCARD_PROTOCOL_UNDEFINED
            )
            .into_inner()
        )
    );

    // Windows zeroes the other fields instead.
    let zeroed = return_round_trip(
        ScardIoCtlCode::Transmit,
        &TransmitReturn::recv_probe(ReturnCode::RemovedCard, None, 0),
    );
    assert_eq!(zeroed.return_code(), ReturnCode::RemovedCard);
}

#[test]
fn scard_unknown_return_code_is_reported_as_unknown_error() {
    let pdu = rpce_frame(&u32s(&[0x8010_00FF]));
    let decoded = ScardReturn::decode(ScardIoCtlCode::BeginTransaction, &mut ReadCursor::new(&pdu)).unwrap();
    assert_eq!(decoded.return_code(), ReturnCode::UnknownError);
}

#[test]
fn scard_return_decode_rejects_inconsistent_lengths() {
    // ListReaders_Return: cBytes = 4 but the referent says 6.
    let mut body = u32s(&[0, 4, 0x0002_0000, 6]);
    body.extend([b'A', 0, 0, 0, 0, 0, 0, 0]);
    let pdu = rpce_frame(&body);
    assert!(ScardReturn::decode(ScardIoCtlCode::ListReadersA, &mut ReadCursor::new(&pdu)).is_err());
}

#[test]
fn rdpdr_server_sends_the_configured_capabilities() {
    let capabilities = vec![
        CapabilityMessage::new_general(0),
        CapabilityMessage::new_smartcard(),
        CapabilityMessage::new_printer(),
    ];
    let mut server = RdpdrServer::with_capabilities(Box::new(NoopRdpdrServerBackend), capabilities.clone());

    let started = server.start().unwrap();
    let client_id = read_u32(&started[0].encode_unframed_pdu().unwrap()[4..]);
    let announce_reply = encode_vec(&RdpdrPdu::VersionAndIdPdu(VersionAndIdPdu {
        version_major: 1,
        version_minor: VERSION_MINOR_RDP51,
        client_id,
        kind: VersionAndIdPduKind::ClientAnnounceReply,
    }))
    .unwrap();
    server.process(&announce_reply).unwrap();
    let name_request = encode_vec(&RdpdrPdu::ClientNameRequest(ClientNameRequest::new(
        "client".to_owned(),
        ClientNameRequestUnicodeFlag::Unicode,
    )))
    .unwrap();
    let replies = server.process(&name_request).unwrap();

    let RdpdrPdu::CoreCapability(request) = ironrdp_core::decode(&replies[0].encode_unframed_pdu().unwrap()).unwrap()
    else {
        panic!("expected the server capability request");
    };
    assert_eq!(request.kind, CoreCapabilityKind::ServerCoreCapabilityRequest);
    assert_eq!(request.capabilities, capabilities);
}

#[test]
fn device_announce_header_exposes_the_device_type() {
    use ironrdp_rdpdr::pdu::efs::{DeviceAnnounceHeader, DeviceType};

    assert_eq!(DeviceAnnounceHeader::new_smartcard(1).device_type(), DeviceType::Smartcard);
    assert_eq!(
        DeviceAnnounceHeader::new_printer(2, "Lobby".to_owned()).device_type(),
        DeviceType::Print
    );
}

#[test]
fn rdpdr_server_request_returns_the_completion_id_it_sends() {
    let mut server = RdpdrServer::new(Box::new(NoopRdpdrServerBackend));
    handshake_to_active(&mut server);

    let call = ScardCall::EstablishContextCall(EstablishContextCall { scope: Scope::User });
    let mut ids = Vec::new();
    for _ in 0..2 {
        let (completion_id, messages) = server
            .request(RdpdrServerMessage::DeviceControl {
                device_id: 1,
                file_id: 0,
                io_control_code: ScardIoCtlCode::EstablishContext.into(),
                input_buffer: call.encode(ScardIoCtlCode::EstablishContext).unwrap(),
                output_buffer_length: 2048,
            })
            .unwrap();
        assert_eq!(completion_id, completion_id_of(&messages[0]));
        ids.push(completion_id);
    }
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn device_control_response_output_bytes_decode_as_a_scard_return() {
    let ret = encode_vec(&ConnectReturn::new(
        ReturnCode::Success,
        handle(),
        CardProtocol::SCARD_PROTOCOL_T1,
    ))
    .unwrap();
    let mut completion = u32::try_from(ret.len()).unwrap().to_le_bytes().to_vec(); // OutputBufferLength
    completion.extend_from_slice(&ret);

    let device_io_reply = DeviceIoResponse {
        device_id: 1,
        completion_id: 5,
        io_status: NtStatus::SUCCESS,
    };
    let response = DeviceControlResponse::decode(device_io_reply.clone(), &mut ReadCursor::new(&completion)).unwrap();
    let output = response.output_bytes().unwrap();
    assert_eq!(output, ret);

    let ScardReturn::Connect(connect) =
        ScardReturn::decode(ScardIoCtlCode::ConnectW, &mut ReadCursor::new(&output)).unwrap()
    else {
        panic!("expected Connect_Return");
    };
    assert_eq!(connect.handle, handle());

    let empty = DeviceControlResponse::decode(device_io_reply, &mut ReadCursor::new(&0u32.to_le_bytes())).unwrap();
    assert!(empty.output_bytes().unwrap().is_empty());
}
