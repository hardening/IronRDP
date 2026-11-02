//! Server side of [MS-RDPESC]: encoding the `*_Call` structures a server sends in a smart card
//! `DeviceControlRequest`, and decoding the `*_Return` structures the client completes it with.
//!
//! The layouts follow FreeRDP's `smartcard_pack.c` (the `smartcard_pack_*_call` and
//! `smartcard_unpack_*_return` functions), which interoperates with Windows clients:
//! - a unique pointer is NULL when its referent is empty (`smartcard_ndr_pointer_write`);
//! - a byte array referent is a conformant array: its count, the bytes, then padding to a
//!   multiple of 4 (`NDR_PTR_SIMPLE`);
//! - a string referent is a conformant varying string: count, offset (0), count, the
//!   NUL-terminated string, then padding (`NDR_PTR_FULL`).
//!
//! Only the calls a PC/SC front end needs are encoded (contexts, readers, status changes,
//! connections, transactions, transmit, control, attributes, status, state); the reader group
//! management, card cache, card location and reader icon calls are not.
//!
//! [MS-RDPESC]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpesc/0428ca28-b4dc-46a3-97c3-01887fa44a90

use ironrdp_core::{
    DecodeResult, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_size, invalid_field_err, other_err,
};
use ironrdp_pdu::utils::{
    CharacterSet, encoded_multistring_len, encoded_str_len, read_multistring_from_cursor, write_multistring_to_cursor,
    write_string_to_cursor,
};
use tracing::warn;

use super::ndr::{self, Decode as _};
use super::{
    CardProtocol, CardState, ConnectReturn, ControlReturn, EstablishContextReturn, GetAttribReturn,
    GetStatusChangeReturn, ListReadersReturn, LongReturn, ReaderStateCommonCall, ReconnectReturn, ReturnCode,
    SCardIORequest, ScardCall, ScardContext, ScardHandle, ScardIoCtlCode, Scope, StateReturn, StatusReturn,
    TransmitReturn, rpce,
};

/// MS-RDPESC `cBytes` / `cbAttrLen` / `cbDataLen` upper bound.
const MAX_BYTES: u32 = 65_536;
/// MS-RDPESC `cbRecvLength` / `cbOutBufferSize` upper bound.
const MAX_IO_BYTES: u32 = 66_560;
/// MS-RDPESC caps `cReaders` at 10 in `GetStatusChange_Return`; one more is accepted for the
/// `\\?PnP?\Notification` pseudo reader that Windows adds.
const MAX_READER_STATES: u32 = 11;

/// The character set of an IOCTL with `A` and `W` variants, `None` for the others.
fn io_ctl_charset(io_ctl_code: ScardIoCtlCode) -> Option<CharacterSet> {
    use ScardIoCtlCode::*;
    match io_ctl_code {
        ListReaderGroupsA
        | ListReadersA
        | IntroduceReaderGroupA
        | ForgetReaderGroupA
        | IntroduceReaderA
        | ForgetReaderA
        | AddReaderToGroupA
        | RemoveReaderFromGroupA
        | LocateCardsA
        | GetStatusChangeA
        | ConnectA
        | StatusA
        | LocateCardsByAtrA
        | ReadCacheA
        | WriteCacheA => Some(CharacterSet::Ansi),
        ListReaderGroupsW
        | ListReadersW
        | IntroduceReaderGroupW
        | ForgetReaderGroupW
        | IntroduceReaderW
        | ForgetReaderW
        | AddReaderToGroupW
        | RemoveReaderFromGroupW
        | LocateCardsW
        | GetStatusChangeW
        | ConnectW
        | StatusW
        | LocateCardsByAtrW
        | ReadCacheW
        | WriteCacheW => Some(CharacterSet::Unicode),
        _ => None,
    }
}

fn charset_of(io_ctl_code: ScardIoCtlCode) -> EncodeResult<CharacterSet> {
    io_ctl_charset(io_ctl_code).ok_or_else(|| other_err!("ScardCall", "IOCTL without a character set"))
}

fn len_u32(len: usize) -> EncodeResult<u32> {
    cast_length!("ScardCall", "length", len)
}

/// Builds the NDR body of a call, keeping track of the pointer index.
#[derive(Default)]
struct NdrWriter {
    buf: Vec<u8>,
    index: u32,
}

impl NdrWriter {
    fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    fn bool(&mut self, value: bool) {
        self.u32(u32::from(value));
    }

    /// A unique pointer: NULL when the referent is absent or empty.
    fn ptr(&mut self, present: bool) {
        if present {
            let ptr = 0x0002_0000 + self.index * 4;
            self.index += 1;
            self.u32(ptr);
        } else {
            self.u32(0);
        }
    }

    fn pad(&mut self) {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }

    /// A conformant byte array referent.
    fn bytes(&mut self, data: &[u8]) -> EncodeResult<()> {
        self.u32(len_u32(data.len())?);
        self.buf.extend_from_slice(data);
        self.pad();
        Ok(())
    }

    /// A conformant varying string referent.
    fn string(&mut self, value: &str, charset: CharacterSet) -> EncodeResult<()> {
        let size = encoded_str_len(value, charset, true);
        let unit = if charset == CharacterSet::Unicode { 2 } else { 1 };
        let count = len_u32(size / unit)?;
        self.u32(count);
        self.u32(0);
        self.u32(count);
        let start = self.buf.len();
        self.buf.resize(start + size, 0);
        write_string_to_cursor(&mut WriteCursor::new(&mut self.buf[start..]), value, charset, true)?;
        self.pad();
        Ok(())
    }

    fn ndr_ptr(&mut self, value: &impl ndr::Encode) -> EncodeResult<()> {
        let start = self.buf.len();
        self.buf.resize(start + value.size_ptr(), 0);
        value.encode_ptr(&mut self.index, &mut WriteCursor::new(&mut self.buf[start..]))
    }

    fn ndr_value(&mut self, value: &impl ndr::Encode) -> EncodeResult<()> {
        let start = self.buf.len();
        self.buf.resize(start + value.size_value(), 0);
        value.encode_value(&mut WriteCursor::new(&mut self.buf[start..]))
    }
}

fn multistring_bytes(strings: &[String], charset: CharacterSet) -> EncodeResult<Vec<u8>> {
    if strings.is_empty() {
        return Ok(Vec::new());
    }
    let mut bytes = vec![0; encoded_multistring_len(strings, charset)];
    write_multistring_to_cursor(&mut WriteCursor::new(&mut bytes), strings, charset)?;
    Ok(bytes)
}

fn scope_value(scope: Scope) -> u32 {
    match scope {
        Scope::User => 0,
        Scope::Terminal => 1,
        Scope::System => 2,
    }
}

/// An encoded call body, framed by [`rpce::Pdu`].
#[derive(Debug)]
struct CallBody {
    name: &'static str,
    bytes: Vec<u8>,
}

impl rpce::HeaderlessEncode for CallBody {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.bytes.len());
        dst.write_slice(&self.bytes);
        Ok(())
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn size(&self) -> usize {
        self.bytes.len()
    }
}

/// See [`ScardCall::encode`].
pub(super) fn encode_call(call: &ScardCall, io_ctl_code: ScardIoCtlCode) -> EncodeResult<Vec<u8>> {
    use ScardIoCtlCode as Io;

    let mut w = NdrWriter::default();
    let name = match (call, io_ctl_code) {
        (ScardCall::AccessStartedEventCall(_), Io::AccessStartedEvent) => {
            w.u32(0); // Unused
            "ScardAccessStartedEvent_Call"
        }
        (ScardCall::EstablishContextCall(call), Io::EstablishContext) => {
            w.u32(scope_value(call.scope));
            "EstablishContext_Call"
        }
        (ScardCall::ContextCall(call), Io::ReleaseContext | Io::IsValidContext | Io::Cancel) => {
            w.ndr_ptr(&call.context)?;
            w.ndr_value(&call.context)?;
            "Context_Call"
        }
        (ScardCall::ListReaderGroupsCall(call), Io::ListReaderGroupsA | Io::ListReaderGroupsW) => {
            w.ndr_ptr(&call.context)?;
            w.bool(call.groups_is_null);
            w.u32(call.groups_size);
            w.ndr_value(&call.context)?;
            "ListReaderGroups_Call"
        }
        (ScardCall::ListReadersCall(call), Io::ListReadersA | Io::ListReadersW) => {
            let groups = multistring_bytes(&call.groups, charset_of(io_ctl_code)?)?;
            w.ndr_ptr(&call.context)?;
            w.u32(len_u32(groups.len())?);
            w.ptr(!groups.is_empty());
            w.bool(call.readers_is_null);
            w.u32(call.readers_size);
            w.ndr_value(&call.context)?;
            if !groups.is_empty() {
                w.bytes(&groups)?;
            }
            "ListReaders_Call"
        }
        (ScardCall::GetStatusChangeCall(call), Io::GetStatusChangeA | Io::GetStatusChangeW) => {
            let charset = charset_of(io_ctl_code)?;
            let count = len_u32(call.states.len())?;
            if count > MAX_READER_STATES {
                return Err(invalid_field_err!(
                    "encode",
                    "GetStatusChange_Call cReaders out of range"
                ));
            }
            w.ndr_ptr(&call.context)?;
            w.u32(call.timeout);
            w.u32(count);
            w.ptr(count > 0);
            w.ndr_value(&call.context)?;
            if count > 0 {
                w.u32(count);
                for state in &call.states {
                    w.ptr(true); // szReader
                    w.u32(state.common.current_state.bits());
                    w.u32(state.common.event_state.bits());
                    w.u32(state.common.atr_length);
                    w.buf.extend_from_slice(&state.common.atr);
                }
                for state in &call.states {
                    w.string(&state.reader, charset)?;
                }
            }
            "GetStatusChange_Call"
        }
        (ScardCall::ConnectCall(call), Io::ConnectA | Io::ConnectW) => {
            w.ptr(true); // szReader
            w.ndr_ptr(&call.common.context)?;
            w.u32(call.common.share_mode);
            w.u32(call.common.preferred_protocols.bits());
            w.string(&call.reader, charset_of(io_ctl_code)?)?;
            w.ndr_value(&call.common.context)?;
            "Connect_Call"
        }
        (ScardCall::ReconnectCall(call), Io::Reconnect) => {
            w.ndr_ptr(&call.handle)?;
            w.u32(call.share_mode);
            w.u32(call.preferred_protocols.bits());
            w.u32(call.initialization);
            w.ndr_value(&call.handle)?;
            "Reconnect_Call"
        }
        (ScardCall::HCardAndDispositionCall(call), Io::BeginTransaction | Io::EndTransaction | Io::Disconnect) => {
            w.ndr_ptr(&call.handle)?;
            w.u32(call.disposition);
            w.ndr_value(&call.handle)?;
            "HCardAndDisposition_Call"
        }
        (ScardCall::TransmitCall(call), Io::Transmit) => {
            let send_extra = &call.send_pci.extra_bytes;
            w.ndr_ptr(&call.handle)?;
            w.u32(call.send_pci.protocol.bits());
            w.u32(len_u32(send_extra.len())?);
            w.ptr(!send_extra.is_empty());
            w.u32(len_u32(call.send_buffer.len())?);
            w.ptr(!call.send_buffer.is_empty());
            w.ptr(call.recv_pci.is_some());
            w.bool(call.recv_buffer_is_null);
            w.u32(call.recv_length);
            w.ndr_value(&call.handle)?;
            if !send_extra.is_empty() {
                w.bytes(send_extra)?;
            }
            if !call.send_buffer.is_empty() {
                w.bytes(&call.send_buffer)?;
            }
            if let Some(recv_pci) = &call.recv_pci {
                w.u32(recv_pci.protocol.bits());
                w.u32(len_u32(recv_pci.extra_bytes.len())?);
                w.ptr(!recv_pci.extra_bytes.is_empty());
                if !recv_pci.extra_bytes.is_empty() {
                    w.bytes(&recv_pci.extra_bytes)?;
                }
            }
            "Transmit_Call"
        }
        (ScardCall::StatusCall(call), Io::StatusA | Io::StatusW) => {
            w.ndr_ptr(&call.handle)?;
            w.bool(call.reader_names_is_null);
            w.u32(call.reader_length);
            w.u32(call.atr_length);
            w.ndr_value(&call.handle)?;
            "Status_Call"
        }
        (ScardCall::StateCall(call), Io::State) => {
            w.ndr_ptr(&call.handle)?;
            w.bool(call.atr_is_null);
            w.u32(call.atr_length);
            w.ndr_value(&call.handle)?;
            "State_Call"
        }
        (ScardCall::ControlCall(call), Io::Control) => {
            w.ndr_ptr(&call.handle)?;
            w.u32(call.control_code);
            w.u32(len_u32(call.in_buffer.len())?);
            w.ptr(!call.in_buffer.is_empty());
            w.bool(call.out_buffer_is_null);
            w.u32(call.out_buffer_size);
            w.ndr_value(&call.handle)?;
            if !call.in_buffer.is_empty() {
                w.bytes(&call.in_buffer)?;
            }
            "Control_Call"
        }
        (ScardCall::GetAttribCall(call), Io::GetAttrib) => {
            w.ndr_ptr(&call.handle)?;
            w.u32(call.attr_id);
            w.bool(call.attr_is_null);
            w.u32(call.attr_length);
            w.ndr_value(&call.handle)?;
            "GetAttrib_Call"
        }
        (ScardCall::SetAttribCall(call), Io::SetAttrib) => {
            w.ndr_ptr(&call.handle)?;
            w.u32(call.attr_id);
            w.u32(len_u32(call.attr.len())?);
            w.ptr(!call.attr.is_empty());
            w.ndr_value(&call.handle)?;
            if !call.attr.is_empty() {
                w.bytes(&call.attr)?;
            }
            "SetAttrib_Call"
        }
        (ScardCall::GetTransmitCountCall(call), Io::GetTransmitCount) => {
            w.ndr_ptr(&call.handle)?;
            w.ndr_value(&call.handle)?;
            "GetTransmitCount_Call"
        }
        _ => {
            return Err(other_err!(
                "ScardCall",
                "call not encodable, or not used with this IOCTL"
            ));
        }
    };

    ironrdp_core::encode_vec(&rpce::Pdu(CallBody { name, bytes: w.buf }))
}

impl TryFrom<u32> for CardState {
    type Error = ironrdp_core::DecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CardState::Unknown),
            1 => Ok(CardState::Absent),
            2 => Ok(CardState::Present),
            3 => Ok(CardState::Swallowed),
            4 => Ok(CardState::Powered),
            5 => Ok(CardState::Negotiable),
            6 => Ok(CardState::SpecificMode),
            _ => Err(invalid_field_err!("try_from", "CardState", "unsupported value")),
        }
    }
}

/// The smart card return code at the start of every `*_Return`.
///
/// A code outside [MS-RDPESC] 2.2.8 is reported as [`ReturnCode::UnknownError`]: failing the
/// whole completion for it would lose the information that the call failed.
fn read_return_code(src: &mut ReadCursor<'_>) -> DecodeResult<ReturnCode> {
    ensure_size!(in: src, size: 4);
    let value = src.read_u32();
    Ok(ReturnCode::try_from(value).unwrap_or_else(|_| {
        warn!(value = format_args!("0x{value:08x}"), "unknown smart card return code");
        ReturnCode::UnknownError
    }))
}

fn read_u32_bounded(src: &mut ReadCursor<'_>, max: u32, field: &'static str) -> DecodeResult<u32> {
    ensure_size!(in: src, size: 4);
    let value = src.read_u32();
    if value > max {
        return Err(invalid_field_err!("decode", field, "out of range"));
    }
    Ok(value)
}

/// A conformant byte array referent whose count must be `expected`.
fn read_bytes(src: &mut ReadCursor<'_>, expected: u32) -> DecodeResult<Vec<u8>> {
    ensure_size!(in: src, size: 4);
    let count = src.read_u32();
    if count != expected {
        return Err(invalid_field_err!(
            "decode",
            "array",
            "mismatched length in NDR pointer and value"
        ));
    }
    let len: usize = cast_length!("ScardReturn", "array length", count)?;
    ensure_size!(in: src, size: len);
    let bytes = src.read_slice(len).to_vec();
    ndr::skip_pad(src)?;
    Ok(bytes)
}

fn read_multistring(src: &mut ReadCursor<'_>, expected: u32, charset: CharacterSet) -> DecodeResult<Vec<String>> {
    let bytes = read_bytes(src, expected)?;
    read_multistring_from_cursor(&mut ReadCursor::new(&bytes), charset)
}

/// Decodes the body after the return code. On failure, MS-RDPESC 2.2.3 zeroes every other field
/// and FreeRDP sends no body at all: a body that doesn't parse then gives `failed`.
fn decode_body<T>(
    src: &mut ReadCursor<'_>,
    body: impl FnOnce(ReturnCode, &mut ReadCursor<'_>) -> DecodeResult<T>,
    failed: impl FnOnce(ReturnCode) -> T,
) -> DecodeResult<T> {
    let return_code = read_return_code(src)?;
    match body(return_code, src) {
        Ok(value) => Ok(value),
        Err(_) if return_code != ReturnCode::Success => Ok(failed(return_code)),
        Err(err) => Err(err),
    }
}

fn decode_establish_context(src: &mut ReadCursor<'_>) -> DecodeResult<EstablishContextReturn> {
    decode_body(
        src,
        |return_code, src| {
            let mut index = 0;
            let mut context = ScardContext::decode_ptr(src, &mut index)?;
            context.decode_value(src, None)?;
            Ok(EstablishContextReturn { return_code, context })
        },
        |return_code| EstablishContextReturn {
            return_code,
            context: ScardContext::empty(),
        },
    )
}

fn decode_list_readers(src: &mut ReadCursor<'_>, encoding: CharacterSet) -> DecodeResult<ListReadersReturn> {
    decode_body(
        src,
        |return_code, src| {
            let c_bytes = read_u32_bounded(src, MAX_BYTES, "cBytes")?;
            let mut index = 0;
            let ptr = ndr::decode_ptr(src, &mut index)?;
            let readers = if ptr == 0 {
                None
            } else {
                Some(read_multistring(src, c_bytes, encoding)?)
            };
            Ok(ListReadersReturn {
                return_code,
                encoding,
                c_bytes,
                readers,
            })
        },
        |return_code| ListReadersReturn {
            return_code,
            encoding,
            c_bytes: 0,
            readers: None,
        },
    )
}

fn decode_get_status_change(src: &mut ReadCursor<'_>) -> DecodeResult<GetStatusChangeReturn> {
    decode_body(
        src,
        |return_code, src| {
            let count = read_u32_bounded(src, MAX_READER_STATES, "cReaders")?;
            let mut index = 0;
            let ptr = ndr::decode_ptr(src, &mut index)?;
            let mut reader_states = Vec::new();
            if ptr != 0 {
                ensure_size!(in: src, size: 4);
                if src.read_u32() != count {
                    return Err(invalid_field_err!(
                        "decode",
                        "rgReaderStates",
                        "mismatched length in NDR pointer and value"
                    ));
                }
                for _ in 0..count {
                    reader_states.push(ReaderStateCommonCall::decode(src)?);
                }
            }
            Ok(GetStatusChangeReturn {
                return_code,
                reader_states,
            })
        },
        |return_code| GetStatusChangeReturn {
            return_code,
            reader_states: Vec::new(),
        },
    )
}

fn decode_connect(src: &mut ReadCursor<'_>) -> DecodeResult<ConnectReturn> {
    decode_body(
        src,
        |return_code, src| {
            let mut index = 0;
            let mut handle = ScardHandle::decode_ptr(src, &mut index)?;
            ensure_size!(in: src, size: 4);
            let active_protocol = CardProtocol::from_bits_retain(src.read_u32());
            handle.decode_value(src, None)?;
            Ok(ConnectReturn {
                return_code,
                handle,
                active_protocol,
            })
        },
        |return_code| ConnectReturn {
            return_code,
            handle: ScardHandle::empty(),
            active_protocol: CardProtocol::SCARD_PROTOCOL_UNDEFINED,
        },
    )
}

fn decode_reconnect(src: &mut ReadCursor<'_>) -> DecodeResult<ReconnectReturn> {
    decode_body(
        src,
        |return_code, src| {
            ensure_size!(in: src, size: 4);
            Ok(ReconnectReturn {
                return_code,
                active_protocol: CardProtocol::from_bits_retain(src.read_u32()),
            })
        },
        |return_code| ReconnectReturn {
            return_code,
            active_protocol: CardProtocol::SCARD_PROTOCOL_UNDEFINED,
        },
    )
}

fn decode_transmit(src: &mut ReadCursor<'_>) -> DecodeResult<TransmitReturn> {
    decode_body(
        src,
        |return_code, src| {
            let mut index = 0;
            let recv_pci_ptr = ndr::decode_ptr(src, &mut index)?;
            let recv_len = read_u32_bounded(src, MAX_IO_BYTES, "cbRecvLength")?;
            let recv_buffer_ptr = ndr::decode_ptr(src, &mut index)?;
            let recv_pci = if recv_pci_ptr == 0 {
                None
            } else {
                let mut pci = SCardIORequest::decode_ptr(src, &mut index)?;
                pci.decode_value(src, None)?;
                Some(pci)
            };
            let recv_buffer = if recv_buffer_ptr == 0 {
                None
            } else {
                Some(read_bytes(src, recv_len)?)
            };
            Ok(TransmitReturn {
                return_code,
                recv_pci,
                recv_buffer,
                recv_len,
            })
        },
        |return_code| TransmitReturn {
            return_code,
            recv_pci: None,
            recv_buffer: None,
            recv_len: 0,
        },
    )
}

fn decode_status(src: &mut ReadCursor<'_>, encoding: CharacterSet) -> DecodeResult<StatusReturn> {
    decode_body(
        src,
        |return_code, src| {
            let reader_c_bytes = read_u32_bounded(src, MAX_BYTES, "cBytes")?;
            let mut index = 0;
            let ptr = ndr::decode_ptr(src, &mut index)?;
            ensure_size!(in: src, size: 4 + 4 + 32);
            let state = CardState::try_from(src.read_u32()).unwrap_or(CardState::Unknown);
            let protocol = CardProtocol::from_bits_retain(src.read_u32());
            let atr = src.read_array::<32>();
            let atr_length = read_u32_bounded(src, 32, "cbAtrLen")?;
            let reader_names = if ptr == 0 {
                None
            } else {
                Some(read_multistring(src, reader_c_bytes, encoding)?)
            };
            Ok(StatusReturn {
                return_code,
                reader_names,
                reader_c_bytes,
                state,
                protocol,
                atr,
                atr_length,
                encoding,
            })
        },
        |return_code| StatusReturn {
            return_code,
            reader_names: None,
            reader_c_bytes: 0,
            state: CardState::Unknown,
            protocol: CardProtocol::SCARD_PROTOCOL_UNDEFINED,
            atr: [0; 32],
            atr_length: 0,
            encoding,
        },
    )
}

fn decode_state(src: &mut ReadCursor<'_>) -> DecodeResult<StateReturn> {
    decode_body(
        src,
        |return_code, src| {
            ensure_size!(in: src, size: 8);
            let state = CardState::try_from(src.read_u32()).unwrap_or(CardState::Unknown);
            let protocol = CardProtocol::from_bits_retain(src.read_u32());
            let atr_len = read_u32_bounded(src, 36, "cbAtrLen")?;
            let mut index = 0;
            let ptr = ndr::decode_ptr(src, &mut index)?;
            let atr = if ptr == 0 {
                None
            } else {
                Some(read_bytes(src, atr_len)?)
            };
            Ok(StateReturn {
                return_code,
                state,
                protocol,
                atr,
                atr_len,
            })
        },
        |return_code| StateReturn {
            return_code,
            state: CardState::Unknown,
            protocol: CardProtocol::SCARD_PROTOCOL_UNDEFINED,
            atr: None,
            atr_len: 0,
        },
    )
}

/// `cb*` length, pointer, then the byte array: Control_Return and GetAttrib_Return.
fn decode_length_and_bytes(
    src: &mut ReadCursor<'_>,
    max: u32,
    field: &'static str,
) -> DecodeResult<(ReturnCode, Option<Vec<u8>>, u32)> {
    decode_body(
        src,
        |return_code, src| {
            let len = read_u32_bounded(src, max, field)?;
            let mut index = 0;
            let ptr = ndr::decode_ptr(src, &mut index)?;
            let bytes = if ptr == 0 { None } else { Some(read_bytes(src, len)?) };
            Ok((return_code, bytes, len))
        },
        |return_code| (return_code, None, 0),
    )
}

/// A `*_Return` decoded from the output buffer of a smart card `DeviceControlResponse` (server
/// side; the client encodes these structures with their `new` functions).
#[derive(Debug, PartialEq, Clone)]
pub enum ScardReturn {
    /// `Long_Return`: the IOCTLs that only return a code (ReleaseContext, IsValidContext,
    /// Cancel, BeginTransaction, EndTransaction, Disconnect, SetAttrib, AccessStartedEvent...).
    Long(LongReturn),
    EstablishContext(EstablishContextReturn),
    /// `ListReaders_Return` and `ListReaderGroups_Return`.
    ListReaders(ListReadersReturn),
    /// `GetStatusChange_Return` and `LocateCards_Return`.
    GetStatusChange(GetStatusChangeReturn),
    Connect(ConnectReturn),
    Reconnect(ReconnectReturn),
    Transmit(TransmitReturn),
    Status(StatusReturn),
    State(StateReturn),
    Control(ControlReturn),
    GetAttrib(GetAttribReturn),
}

impl ScardReturn {
    /// Decodes the output buffer of the completion of a `DeviceControlRequest` with
    /// `io_ctl_code` (see [`super::super::efs::DeviceControlResponse::output_bytes`]).
    pub fn decode(io_ctl_code: ScardIoCtlCode, src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        use ScardIoCtlCode as Io;

        rpce::decode_headers(src)?;
        let charset = io_ctl_charset(io_ctl_code);
        Ok(match io_ctl_code {
            Io::EstablishContext => Self::EstablishContext(decode_establish_context(src)?),
            Io::ListReadersA | Io::ListReadersW | Io::ListReaderGroupsA | Io::ListReaderGroupsW => {
                Self::ListReaders(decode_list_readers(src, charset.unwrap_or(CharacterSet::Unicode))?)
            }
            Io::GetStatusChangeA
            | Io::GetStatusChangeW
            | Io::LocateCardsA
            | Io::LocateCardsW
            | Io::LocateCardsByAtrA
            | Io::LocateCardsByAtrW => Self::GetStatusChange(decode_get_status_change(src)?),
            Io::ConnectA | Io::ConnectW => Self::Connect(decode_connect(src)?),
            Io::Reconnect => Self::Reconnect(decode_reconnect(src)?),
            Io::Transmit => Self::Transmit(decode_transmit(src)?),
            Io::StatusA | Io::StatusW => Self::Status(decode_status(src, charset.unwrap_or(CharacterSet::Unicode))?),
            Io::State => Self::State(decode_state(src)?),
            Io::Control => {
                let (return_code, out_buffer, out_len) = decode_length_and_bytes(src, MAX_IO_BYTES, "cbOutBufferSize")?;
                Self::Control(ControlReturn {
                    return_code,
                    out_buffer,
                    out_len,
                })
            }
            Io::GetAttrib => {
                let (return_code, attr, attr_len) = decode_length_and_bytes(src, MAX_BYTES, "cbAttrLen")?;
                Self::GetAttrib(GetAttribReturn {
                    return_code,
                    attr,
                    attr_len,
                })
            }
            Io::ReleaseContext
            | Io::IsValidContext
            | Io::Cancel
            | Io::BeginTransaction
            | Io::EndTransaction
            | Io::Disconnect
            | Io::SetAttrib
            | Io::AccessStartedEvent
            | Io::ReleaseTartedEvent
            | Io::IntroduceReaderGroupA
            | Io::IntroduceReaderGroupW
            | Io::ForgetReaderGroupA
            | Io::ForgetReaderGroupW
            | Io::IntroduceReaderA
            | Io::IntroduceReaderW
            | Io::ForgetReaderA
            | Io::ForgetReaderW
            | Io::AddReaderToGroupA
            | Io::AddReaderToGroupW
            | Io::RemoveReaderFromGroupA
            | Io::RemoveReaderFromGroupW
            | Io::WriteCacheA
            | Io::WriteCacheW => Self::Long(LongReturn {
                return_code: read_return_code(src)?,
            }),
            Io::ReadCacheA | Io::ReadCacheW | Io::GetTransmitCount | Io::GetReaderIcon | Io::GetDeviceTypeId => {
                return Err(other_err!("ScardReturn", "return structure not decoded"));
            }
        })
    }

    /// The smart card return code of the call.
    pub fn return_code(&self) -> ReturnCode {
        match self {
            ScardReturn::Long(r) => r.return_code,
            ScardReturn::EstablishContext(r) => r.return_code,
            ScardReturn::ListReaders(r) => r.return_code,
            ScardReturn::GetStatusChange(r) => r.return_code,
            ScardReturn::Connect(r) => r.return_code,
            ScardReturn::Reconnect(r) => r.return_code,
            ScardReturn::Transmit(r) => r.return_code,
            ScardReturn::Status(r) => r.return_code,
            ScardReturn::State(r) => r.return_code,
            ScardReturn::Control(r) => r.return_code,
            ScardReturn::GetAttrib(r) => r.return_code,
        }
    }
}
