# auto-protobuf-struct-generator

[English](README.md) | [简体中文](README.zh-CN.md)

这是一个面向 IDA Pro 9.2 的 IDAPython 插件，用于从 ELF 和 PE 二进制文件中扫描 Protobuf 相关描述信息，并重建 `.proto` 文件与 Python protobuf 模块。

## 功能

插件会始终先输出：

- `{binary_name}.proto`

随后尝试调用 `protoc` 生成标准 Python 输出：

- `{binary_name}_pb2.py`

如果系统中没有 `protoc`，或者编译失败，则会回退生成：

- `{binary_name}_pb.py`

## 当前支持范围

当前实现参考了 `protobuf_rev`，并整合了多种恢复策略：

- C++ protobuf
  - 扫描嵌入的 `FileDescriptorProto` 数据
- Go protobuf
  - 扫描 gzip 压缩的描述符
- 通用 raw descriptor
  - 扫描序列化后的 `FileDescriptorProto` 数据块
- `protobuf-c`
  - 扫描 `ProtobufCMessageDescriptor` 和 `ProtobufCEnumDescriptor`
  - 将其重建为 `.proto`

## 支持目标

- IDA Pro 9.2
- ELF / PE
- 32 位 / 64 位
- 小端 / 大端

## 限制

- IDA 当前使用的 Python 环境必须能够导入 `google.protobuf`
- 如果希望生成标准 `*_pb2.py`，需要保证 `protoc` 已经在 `PATH` 中
- 如果目标二进制已经剥离描述符，且未使用 `protobuf-c` 布局，则无法完整恢复定义

## 安装

将以下文件复制到 IDA 的 `plugins` 目录，或者放入一个单独的插件子目录中：

- `ida_auto_protobuf_plugin.py`
- `ida-plugin.json`

如果 IDA 使用的 Python 环境尚未安装 `protobuf`：

```powershell
python -m pip install protobuf
```

如果你希望插件直接生成 `*_pb2.py`，请先确认 `protoc` 可用：

```powershell
protoc --version
```

## 使用方法

1. 用 IDA Pro 9.2 打开目标 ELF 或 PE 文件。
2. 等待自动分析完成。
3. 在 `Edit -> Plugins -> Auto Protobuf Struct Generator` 中运行插件，或按 `Ctrl+Alt+P`。
4. 插件会在输入二进制所在目录输出 `.proto` 文件，并在可行时优先生成 `*_pb2.py`。

## 输出示例

```proto
syntax = "proto2";

message devicemsg {
  required sint64 actionid = 1;
  required sint64 msgidx = 2;
  required sint64 msgsize = 3;
  required bytes msgcontent = 4;
}
```

## IDA 9.2 说明

该插件遵循 IDA 9.x 推荐的插件结构：

- `plugin_t -> plugmod_t` 生命周期
- 使用 `PLUGIN_ENTRY()` 作为入口
- 提供 `ida-plugin.json` 元数据
- 使用 `PLUGIN_MULTI` 支持多 IDB

## 参考

- Hex-Rays: How to create a plugin in IDAPython
  - https://docs.hex-rays.com/developer-guide/idapython/how-to-create-a-plugin
- Hex-Rays IDAPython 文档
  - https://python.docs.hex-rays.com/
- 参考项目：`protobuf_rev`
  - https://github.com/InkeyP/protobuf_rev
