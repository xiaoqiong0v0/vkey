# 虚拟 FIDO2 安全密钥 / Windows Passkey Provider 证据（检索时间 2026-10-26）

## (1) Linux uhid 可行性
- Chromium FIDO HID 发现只按 usage page 过滤：`device/fido/hid/fido_hid_discovery.cc:43-48`（`kFidoUsagePage = 0xf1d0`，`filter_.SetUsagePage`）。
- 附加条件仅报告尺寸：同文件 `:21-26`（`max_input/output_report_size > kHidInitPacketHeaderSize && <= kHidMaxPacketSize`），`:77` 先 `filter_.Matches` 再 `ReportSizesSufficient`。
- 唯一的 VID/PID 逻辑是「忽略名单」（denylist，不是 allowlist）：`:81-86` `ignore_list_.contains(vid_pid)` → return；名单由 embedder 通过 `fido_discovery_factory.cc:163-165 set_hid_ignore_list()` 注入，默认空。
- usage page 常量：`services/device/public/mojom/hid.mojom:49 const uint16 kPageFido = 0xF1D0;`
- 结论：任何能出现在 hidraw 上、报告描述符含 0xF1D0 顶层 collection、报告尺寸合规的设备都会被 Chrome 当 U2F/FIDO HID 认证器。uhid 满足该形态（kernel docs UHID: `UHID_CREATE2` 创建内部 HID 设备）。

### 现有实现
- `bulwarkid/virtual-fido`：**不是 uhid**，是 USB/IP + `vhci-hcd`，需 root（README「Support for both Windows and Linux through USB/IP」「sudo modprobe vhci-hcd」「requires elevated permissions」）。
- `soft-fido2`（Rust，`soft-fido2-transport` crate）：**真 uhid**。docs.rs `soft_fido2_transport::uhid`：`UhidDevice::create_fido_device()`，前置 `modprobe uhid`、需 `/dev/uhid` 权限（通常 fido 组）。
- `BryanJacobs/fido2-hid-bridge`：uhid + python-fido2，README 明示「uses the Linux kernel UHID device facility」「might need to be root … permissions on /dev/uhid」，并注明用途是让只支持 USB-HID 的应用（如 Firefox）用 PC/SC 认证器。
- `pando85/passless`（基于 soft-fido2，跑成 uhid 设备）、`ellerh/softfido`（USBIP + SoftHSM）、PyPI `soft-fido2`（Python 实现）、`python-uhid`（UHID API 封装）。
- 权限坑：Chrome 直接 open devnode — `services/device/hid/hid_service_linux.cc:458-466`（`base::File(device_path, FLAG_OPEN|READ|WRITE)`，处理 `FILE_ERROR_ACCESS_DENIED`）。uhid 生成的 hidraw 需自行授权（udev 规则 / 组 / root），否则浏览器打不开。

## (2) Windows 侧（无 USB 仿真）
- 官方支持第三方 passkey provider：learn.microsoft.com「WebAuthn APIs」页原文「starting in Windows 11 version 24H2 WebAuthn APIs support plugin passkey managers」；API 全在 `webauthnplugin.h` / `WebAuthnPlugin.dll`。
- `WebAuthNPluginAddAuthenticator` 文档原文：「adds the plugin authenticator to the system so that Windows can route WebAuthn operations to it and expose its metadata to supported experiences」。
- 形态：打包应用（`Package.appxmanifest` + Clsid）+ COM 注册实现 `IPluginAuthenticator`，再调 `WebAuthNPluginAddAuthenticator`；凭证增删 `WebAuthNPluginAuthenticatorAdd/RemoveCredentials`；UV 走 Windows Hello（`WebAuthNPluginPerformUserVerification`）——见 Passkey Manager sample 页与 `microsoft/webauthn` 的 `webauthnplugin.h`（`WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS.pwszPluginClsId`、`pwszPluginRpId`）。
- 用户开关位置：Settings > Accounts > Passkeys > Advanced options（MS「Plugin passkey manager support」页）。
- 1Password：官方支持页「Turn on 1Password as a passkey manager in the Windows Settings app」「Save and sign in with passkeys in your browser」；MS 博文点名 1Password、Bitwarden 合作。
- 浏览器侧：Windows 上 Chromium 走系统 API（`device/fido/win/authenticator.cc:47-48 is_platform_device=kBoth`、`:182 EnumeratePlatformCredentials`），因此由 Windows 路由到插件认证器；未在 Chromium 代码中找到显式 plugin-authenticator 分支。

## (3) Linux 浏览器枚举与过滤
- Chrome：`services/device/hid/hid_service_linux.cc:52/256/260` — udev 枚举 subsystem `hidraw`，取 devnode；报告描述符从 sysfs（`:332-333`）解析成 collections；FIDO 过滤只看 usage page（见 (1)）。**不是 hidapi**，是 Chromium 自带 //device/hid 后端。
- Firefox：`mozilla/authenticator-rs` `src/transport/linux/monitor.rs:16,66-67` udev `match_subsystem("hidraw")`；`src/transport/linux/hidraw.rs:44-48 is_u2f_device()` → `hidproto.rs:167-181 has_fido_usage()` 比对 `consts.rs FIDO_USAGE_PAGE=0xf1d0` + `FIDO_USAGE_U2FHID=0x01`。monitor/device 中无 vendor/product 判断。
- 已知坑：Snap 版 Firefox 的沙盒会挡 hidraw，需设备进 snap 白名单（fido-dev 邮件列表）。

## 未验证/缺口
- Chromium 中 `set_hid_ignore_list` 的调用点（grep.app 429，未取到）；只证实它是可选 denylist。
- Firefox(Win) 是否能看见 Windows plugin provider（Firefox 用自带 HID 后端；其 Win 平台认证器实现未核）。
- uhid hidraw 是否被 systemd-logind uaccess 自动授权（未实测；仅知两个实现都要求显式提权）。
