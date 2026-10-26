# CTAP2.2 vs CTAP1/U2F 判定 证据摘录
Spec: https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html (PS, 2025-07-14; title: Client to Authenticator Protocol (CTAP))

## 1) §11.2.9.1.3 CTAPHID_INIT (0x06) 响应
Response at success: BCNT=17 (see note below); DATA=8-byte nonce; DATA+8=4-byte channel ID; DATA+12=CTAPHID protocol version identifier; DATA+13/14/15=Major/Minor/Build device version; DATA+16=Capabilities flags
"A CTAPHID host SHALL accept a response size that is longer than the anticipated size to allow for future extensions" ... "The capability flags value is a bitfield where the following bits values are defined. Unused values are reserved for future use and MUST be set to zero by device vendors."
CAPABILITY_WINK 0x01 "If set to 1, authenticator implements CTAPHID_WINK function"
CAPABILITY_CBOR 0x04 "If set to 1, authenticator implements CTAPHID_CBOR function"
CAPABILITY_NMSG 0x08 "If set to 1, authenticator DOES NOT implement CTAPHID_MSG function"

## 2) §6.4 authenticatorGetInfo (0x04)
"Using this method, platforms can request that the authenticator report a list of its supported protocol versions and extensions, its AAGUID, and other aspects of its overall capabilities." / "This method takes no inputs."
versions (0x01) Array of strings Required — "List of supported versions. Supported versions are: "FIDO_2_1" ... "FIDO_2_0" ... "FIDO_2_1_PRE" for CTAP2.1 Preview features and "U2F_V2" for CTAP1/U2F authenticators." (PS 文本未列 FIDO_2_2，但 §9 Mandatory features / §7.2.x 使用 FIDO_2_2)
extensions (0x02) Array of strings Optional — "List of supported extensions."
aaguid (0x03) Byte String Required — "The claimed AAGUID. 16 bytes in length and encoded the same as MakeCredential AuthenticatorData, as specified in [WebAuthn]."
options (0x04) Map Optional — "List of supported options." / "All options are in the form key-value pairs with string IDs and boolean values. When an option ID is not present, the default is applied per table below."
maxMsgSize (0x05) Unsigned Integer Optional — "Maximum message size supported by the authenticator."
§11.2.4: "By default, authenticators MUST support messages of at least 1024 bytes." / "Clients, platforms, and servers MUST NOT send messages larger than 1024 bytes unless the authenticator's maxMsgSize indicates support for the larger message size." / §6.4 未给上限；§11.2.4 由 HID 分片推导上限 64-7+128*(64-5)=7609
§11.2.4 亦: "If map keys are present that an implementation does not understand, they MUST be ignored."

## 3) 客户端如何判定
§4 Protocol Overview 步骤2: "The platform gets information about the authenticator using the authenticatorGetInfo command, which helps it determine the authenticator's capabilities."（描述性，无 MUST）
§11.3.3 Applet selection（NFC 语境）: "Given legacy support for CTAP1/U2F, the client MUST determine the capabilities of the device at the selection stage."；"If the authenticator implements both CTAP1/U2F and CTAP2, the version information SHALL be the string "U2F_V2" ... CTAP2-aware clients MAY then issue a CTAP authenticatorGetInfo command to determine if the device supports CTAP2 or not."
→ 全文 CAPABILITY_CBOR 仅出现在 §11.2.9.1.3 位定义；不存在 "capabilities 不含 CBOR 就必须用 CTAP1" 这类 HID 侧规范语句。

## 4) Chromium (main, 检索时)
device/fido/fido_device.cc:32-45 DiscoverSupportedProtocolAndDeviceInfo — 先将 supported_protocol_ 置 kCtap2，再 DeviceTransact({kAuthenticatorGetInfo})
device/fido/fido_device.cc:51-70 OnDeviceInfoReceived — ReadCTAPGetInfoResponse；解析失败 或 !versions.contains(ProtocolVersion::kCtap2) → supported_protocol_ = kU2f; needs_explicit_wink_ = true（回退 CTAP1/U2F）
device/fido/hid/fido_hid_device.cc:248-268 ParseInitReply — 注释列出 payload 16 = Capabilities；payload.size()!=17 → nullopt；capabilities_ = payload[16]
device/fido/hid/fido_hid_device.cc:30 kWinkCapability = 0x01；:124-129 仅用 (capabilities_ & kWinkCapability)；main 上无 0x04/CBOR 位判断
device/fido/hid/fido_hid_device.cc:51-53 DeviceTransact 按 supported_protocol() 选 kCbor / kMsg
device/fido/device_response_converter.cc:378,405-457 ReadCTAPGetInfoResponse — versions 缺失/重复/非字符串、aaguid 缺失或非 16 字节 → nullopt
device/fido/ctap2_device.cc 与 device/fido/hid/ctap_hid_device.cc 不存在：main 及 refs/branch-heads/5060,5249,5481,5563,5672,5800,5938,6099,6167,6239,6261,6341,6478,6699,6834,6943,7049 全 404

本地副本: .tmp/scratch/ctap22_spec.html / ctap22_spec.txt / fido_device.cc / fido_hid_device.cc / device_response_converter.cc
