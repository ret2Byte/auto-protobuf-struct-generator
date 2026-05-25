# auto-protobuf-struct-generator

[English](README.md) | [简体中文](README.zh-CN.md)

An IDAPython plugin for IDA Pro 9.2 that scans ELF and PE binaries for Protobuf-related descriptor data and reconstructs `.proto` files plus Python protobuf modules.

## Features

The plugin always writes:

- `{binary_name}.proto`

It then tries to call `protoc` to generate the standard Python output:

- `{binary_name}_pb2.py`

If `protoc` is not available or compilation fails, it falls back to:

- `{binary_name}_pb.py`

## Current Coverage

The implementation is inspired by `protobuf_rev` and combines several recovery strategies:

- C++ protobuf
  - Scan embedded `FileDescriptorProto` data
- Go protobuf
  - Scan gzip-compressed descriptors
- Generic raw descriptor
  - Scan serialized `FileDescriptorProto` blobs
- `protobuf-c`
  - Scan `ProtobufCMessageDescriptor` and `ProtobufCEnumDescriptor`
  - Rebuild them into `.proto`

## Supported Targets

- IDA Pro 9.2
- ELF / PE
- 32-bit / 64-bit
- Little-endian / big-endian

## Limitations

- The active IDA Python environment must be able to import `google.protobuf`
- To generate standard `*_pb2.py` output, `protoc` must be available in `PATH`
- If a target binary strips descriptors and does not use `protobuf-c` layouts, complete recovery is not possible

## Installation

Copy these files into the IDA `plugins` directory, or into a dedicated plugin subdirectory:

- `ida_auto_protobuf_plugin.py`
- `ida-plugin.json`

If the Python environment used by IDA does not have `protobuf` installed:

```powershell
python -m pip install protobuf
```

If you want the plugin to generate `*_pb2.py` directly, verify that `protoc` is available:

```powershell
protoc --version
```

## Usage

1. Open a target ELF or PE file in IDA Pro 9.2.
2. Wait for auto-analysis to finish.
3. Run `Edit -> Plugins -> Auto Protobuf Struct Generator`, or press `Ctrl+Alt+P`.
4. The plugin writes `.proto` output beside the input binary and prefers generating `*_pb2.py` when possible.

## Example Output

```proto
syntax = "proto2";

message devicemsg {
  required sint64 actionid = 1;
  required sint64 msgidx = 2;
  required sint64 msgsize = 3;
  required bytes msgcontent = 4;
}
```

## IDA 9.2 Notes

This plugin follows the recommended IDA 9.x plugin structure:

- `plugin_t -> plugmod_t` lifecycle
- `PLUGIN_ENTRY()` entry point
- `ida-plugin.json` metadata
- `PLUGIN_MULTI` for multi-IDB support

## References

- Hex-Rays: How to create a plugin in IDAPython
  - https://docs.hex-rays.com/developer-guide/idapython/how-to-create-a-plugin
- Hex-Rays IDAPython documentation
  - https://python.docs.hex-rays.com/
- Reference project: `protobuf_rev`
  - https://github.com/InkeyP/protobuf_rev
