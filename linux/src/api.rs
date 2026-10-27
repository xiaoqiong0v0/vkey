//! vkeyd HTTP 客户端（`shared/protocol.md` §3–§4）。
//!
//! 单线程阻塞实现（ureq），不引入 tokio。所有需要鉴权的请求都按
//! §3.1 的签名串签名，并携带 `Authorization` / `X-Vkey-Ts` / `X-Vkey-Sig`。

use crate::config;
use crate::crypto::{self, ED25519_SEED_LEN};
use crate::policy::{KdfParams, PolicyResponse};
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// 删除主密码包裹时必须回传的确认串（与服务端一致）。
pub const REMOVE_PASSWORD_CONFIRM: &str = "remove-master-password";

/// API 错误（HTTP 状态 + 协议错误码）。
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("HTTP {status} {code}: {message}")]
    Http {
        status: u16,
        code: String,
        message: String,
    },
    #[error("网络请求失败: {0}")]
    Transport(String),
    #[error("{0}")]
    Other(String),
}

impl ApiError {
    /// HTTP 状态码（传输层失败时为 None）。
    pub fn status(&self) -> Option<u16> {
        match self {
            ApiError::Http { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// 协议错误码。
    pub fn code(&self) -> Option<&str> {
        match self {
            ApiError::Http { code, .. } => Some(code),
            _ => None,
        }
    }
}

/// 设备鉴权材料：Ed25519 私钥 + 32B token。
#[derive(Clone)]
pub struct Auth {
    pub signing_key: SigningKey,
    pub token: Vec<u8>,
}

impl Auth {
    /// 从 32B Ed25519 种子与 token 构造。
    pub fn new(seed: &[u8], token: Vec<u8>) -> Result<Self> {
        if seed.len() != ED25519_SEED_LEN {
            return Err(anyhow!("Ed25519 种子必须 {ED25519_SEED_LEN} 字节"));
        }
        if token.len() != crypto::TOKEN_LEN {
            return Err(anyhow!("token 必须 {} 字节", crypto::TOKEN_LEN));
        }
        Ok(Self {
            signing_key: crypto::device_signing_key(seed)?,
            token,
        })
    }

    /// 从 identity.json 中的 base64url 字段构造。
    pub fn from_encoded(seed_b64: &str, token_b64: &str) -> Result<Self> {
        let seed = crypto::b64_decode(seed_b64).context("ed25519_seed 解码失败")?;
        let token = crypto::b64_decode(token_b64).context("token 解码失败")?;
        Self::new(&seed, token)
    }
}

/// 请求体：`POST /api/v1/auth/token`。
#[derive(Debug, Serialize)]
pub struct AuthTokenRequest<'a> {
    pub username: &'a str,
    pub verifier: &'a str,
    pub device: AuthDevice<'a>,
}

/// 认证请求中的设备描述。
#[derive(Debug, Serialize)]
pub struct AuthDevice<'a> {
    pub name: &'a str,
    pub platform: &'a str,
    pub pubkey: &'a str,
}

/// 响应：`POST /api/v1/auth/token`。
#[derive(Debug, Clone, Deserialize)]
pub struct AuthTokenResponse {
    pub token: String,
    pub device_id: String,
    #[serde(default)]
    pub pw_salt: Option<String>,
    #[serde(default)]
    pub wrapped_key: Option<String>,
}

/// 响应：`GET /api/v1/health`。
#[derive(Debug, Clone, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub items: i64,
    pub devices: i64,
}

/// 线上条目（GET /items 与 POST /items 共用的字段超集）。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ItemWire {
    pub id: String,
    pub kind: String,
    pub rp_id: String,
    #[serde(default)]
    pub ct: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub version: i64,
    #[serde(default)]
    pub updated_at: i64,
    #[serde(default)]
    pub deleted_at: i64,
}

/// 响应：`GET /api/v1/items`。
#[derive(Debug, Clone, Deserialize)]
pub struct ItemsPage {
    pub items: Vec<ItemWire>,
    pub next: i64,
}

/// 请求体中的单条推送条目。
#[derive(Debug, Clone, Serialize)]
pub struct PushItem {
    pub id: String,
    pub kind: String,
    pub rp_id: String,
    pub ct: String,
    pub nonce: String,
    pub base_version: i64,
    pub updated_at: i64,
    pub deleted_at: i64,
}

/// 单条推送结果。
#[derive(Debug, Clone, Deserialize)]
pub struct PushResult {
    pub id: String,
    pub version: i64,
    pub status: String,
    #[serde(default)]
    pub reason: String,
}

/// 请求体：`POST /api/v1/pair/claim`。
#[derive(Debug, Serialize)]
pub struct PairClaimRequest<'a> {
    pub code: &'a str,
    pub name: &'a str,
    pub platform: &'a str,
    pub pubkey: &'a str,
}

/// 响应：`POST /api/v1/pair/claim`。
#[derive(Debug, Clone, Deserialize)]
pub struct PairClaimResponse {
    pub token: String,
    pub device_id: String,
    pub blob: String,
    #[serde(default)]
    pub pw_salt: Option<String>,
    #[serde(default)]
    pub wrapped_key: Option<String>,
    pub code_id: String,
}

/// 请求体：`POST /api/v1/pair/new`。
#[derive(Debug, Serialize)]
pub struct PairNewRequest<'a> {
    pub code_id: &'a str,
    pub code: &'a str,
    pub blob: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pw_salt: Option<&'a str>,
}

/// 响应：`POST /api/v1/pair/new`。
#[derive(Debug, Clone, Deserialize)]
pub struct PairNewResponse {
    pub code_id: String,
    pub code: String,
    pub expires_at: i64,
}

/// 错误响应体。
#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    code: String,
    message: String,
}

/// 请求体：`POST /api/v1/auth/password`。
#[derive(Debug, Serialize)]
struct SetPasswordRequest<'a> {
    wrapped_key: &'a str,
    pw_salt: &'a str,
}

/// 只表示成功的响应体（`{ok:true}`）。
#[derive(Debug, Deserialize)]
struct OkResponse {
    ok: bool,
}

/// vkeyd HTTP 客户端。
#[derive(Clone)]
pub struct ApiClient {
    base: String,
    agent: ureq::Agent,
}

impl ApiClient {
    /// 构造客户端。`server_url` 允许带尾随 `/`，也允许 `http://`（回环测试）。
    pub fn new(server_url: &str) -> Result<Self> {
        let base = server_url.trim().trim_end_matches('/').to_string();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            return Err(anyhow!("server_url 必须以 http:// 或 https:// 开头"));
        }
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .build();
        Ok(Self { base, agent })
    }

    /// 服务端基址。
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// `GET /api/v1/policy`（免鉴权）。
    pub fn policy(&self) -> Result<PolicyResponse> {
        self.get_json("/api/v1/policy", None)
    }

    /// `GET /api/v1/health`（免鉴权）。
    pub fn health(&self) -> Result<HealthResponse> {
        self.get_json("/api/v1/health", None)
    }

    /// `POST /api/v1/auth/token`（免鉴权）。
    pub fn auth_token(
        &self,
        username: &str,
        verifier_b64: &str,
        device_name: &str,
        platform: &str,
        pubkey_b64: &str,
    ) -> Result<AuthTokenResponse> {
        let body = AuthTokenRequest {
            username,
            verifier: verifier_b64,
            device: AuthDevice {
                name: device_name,
                platform,
                pubkey: pubkey_b64,
            },
        };
        let bytes = serde_json::to_vec(&body)?;
        self.post_json("/api/v1/auth/token", &bytes, None)
    }

    /// `GET /api/v1/items?since=<n>`（签名）。
    pub fn get_items(&self, auth: &Auth, since: i64) -> Result<ItemsPage> {
        if since < 0 {
            return Err(anyhow!("since 必须是非负整数"));
        }
        let path = format!("/api/v1/items?since={since}");
        self.get_json(&path, Some(auth))
    }

    /// `POST /api/v1/items`（签名）。
    pub fn post_items(&self, auth: &Auth, items: &[PushItem]) -> Result<Vec<PushResult>> {
        #[derive(Serialize)]
        struct Body<'a> {
            items: &'a [PushItem],
        }
        #[derive(Deserialize)]
        struct Resp {
            results: Vec<PushResult>,
        }
        let bytes = serde_json::to_vec(&Body { items })?;
        let resp: Resp = self.post_json("/api/v1/items", &bytes, Some(auth))?;
        Ok(resp.results)
    }

    /// `POST /api/v1/pair/claim`（免鉴权）。
    pub fn pair_claim(
        &self,
        code: &str,
        name: &str,
        platform: &str,
        pubkey_b64: &str,
    ) -> Result<PairClaimResponse> {
        let body = PairClaimRequest {
            code,
            name,
            platform,
            pubkey: pubkey_b64,
        };
        let bytes = serde_json::to_vec(&body)?;
        self.post_json("/api/v1/pair/claim", &bytes, None)
    }

    /// `POST /api/v1/pair/new`（签名）。
    pub fn pair_new(
        &self,
        auth: &Auth,
        code_id: &str,
        code_b32: &str,
        blob_b64: &str,
        pw_salt_b64: Option<&str>,
    ) -> Result<PairNewResponse> {
        let body = PairNewRequest {
            code_id,
            code: code_b32,
            blob: blob_b64,
            pw_salt: pw_salt_b64,
        };
        let bytes = serde_json::to_vec(&body)?;
        self.post_json("/api/v1/pair/new", &bytes, Some(auth))
    }

    /// `POST /api/v1/auth/password`（签名）：写入主密码包裹。
    pub fn set_password(
        &self,
        auth: &Auth,
        pw_salt_b64: &str,
        wrapped_key_b64: &str,
    ) -> Result<()> {
        let body = serde_json::to_vec(&SetPasswordRequest {
            wrapped_key: wrapped_key_b64,
            pw_salt: pw_salt_b64,
        })?;
        let resp: OkResponse = self.post_json("/api/v1/auth/password", &body, Some(auth))?;
        if !resp.ok {
            return Err(anyhow!("服务端未确认主密码包裹已写入"));
        }
        Ok(())
    }

    /// `DELETE /api/v1/auth/password`（签名）：清空主密码包裹。
    pub fn clear_password(&self, auth: &Auth) -> Result<()> {
        #[derive(Serialize)]
        struct Body<'a> {
            confirm: &'a str,
        }
        let body = serde_json::to_vec(&Body {
            confirm: REMOVE_PASSWORD_CONFIRM,
        })?;
        let resp: OkResponse = self.delete_json("/api/v1/auth/password", &body, Some(auth))?;
        if !resp.ok {
            return Err(anyhow!("服务端未确认主密码包裹已清除"));
        }
        Ok(())
    }

    /// 带鉴权的 GET。
    fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str, auth: Option<&Auth>) -> Result<T> {
        let url = format!("{}{}", self.base, path);
        let mut req = self.agent.request("GET", &url);
        req = self.apply_auth(req, "GET", path, &[], auth)?;
        let resp = req.call().map_err(map_ureq)?;
        decode_response(resp)
    }

    /// 带鉴权的 POST（body 原样发送，签名使用同一份字节）。
    fn post_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &[u8],
        auth: Option<&Auth>,
    ) -> Result<T> {
        self.send_json("POST", path, body, auth)
    }

    /// 带鉴权的 DELETE（body 原样发送，签名使用同一份字节）。
    fn delete_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &[u8],
        auth: Option<&Auth>,
    ) -> Result<T> {
        self.send_json("DELETE", path, body, auth)
    }

    /// 发送带 body 的请求并按 JSON 解析响应。
    fn send_json<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        auth: Option<&Auth>,
    ) -> Result<T> {
        let url = format!("{}{}", self.base, path);
        let mut req = self
            .agent
            .request(method, &url)
            .set("Content-Type", "application/json; charset=utf-8");
        req = self.apply_auth(req, method, path, body, auth)?;
        let resp = req.send_bytes(body).map_err(map_ureq)?;
        decode_response(resp)
    }

    fn apply_auth(
        &self,
        req: ureq::Request,
        method: &str,
        request_uri: &str,
        body: &[u8],
        auth: Option<&Auth>,
    ) -> Result<ureq::Request> {
        let Some(auth) = auth else {
            return Ok(req);
        };
        let ts = config::now_unix();
        let seed = auth.signing_key.to_bytes();
        let sig = crypto::sign_request(&seed, method, request_uri, body, ts)?;
        Ok(req
            .set(
                "Authorization",
                &format!("Bearer {}", crypto::b64_encode(&auth.token)),
            )
            .set("X-Vkey-Ts", &ts.to_string())
            .set("X-Vkey-Sig", &crypto::b64_encode(&sig)))
    }
}

fn decode_response<T: for<'de> Deserialize<'de>>(resp: ureq::Response) -> Result<T> {
    let text = resp.into_string().context("读取响应体失败")?;
    serde_json::from_str(&text).with_context(|| format!("解析响应 JSON 失败: {text}"))
}

fn map_ureq(err: ureq::Error) -> anyhow::Error {
    match err {
        ureq::Error::Status(status, resp) => {
            let text = resp.into_string().unwrap_or_default();
            let (code, message) = match serde_json::from_str::<ErrorEnvelope>(&text) {
                Ok(env) => (env.error.code, env.error.message),
                Err(_) => ("unknown".to_string(), text),
            };
            ApiError::Http {
                status,
                code,
                message,
            }
            .into()
        }
        ureq::Error::Transport(t) => ApiError::Transport(t.to_string()).into(),
    }
}

/// 方便上层提取 `ApiError` 的 HTTP 状态。
pub fn api_status(err: &anyhow::Error) -> Option<u16> {
    err.downcast_ref::<ApiError>().and_then(|e| e.status())
}

/// 判断错误是否为指定协议码。
pub fn api_code_is(err: &anyhow::Error, code: &str) -> bool {
    err.downcast_ref::<ApiError>()
        .and_then(|e| e.code())
        .map(|c| c == code)
        .unwrap_or(false)
}

// 让 KdfParams 在本模块被引用（serde 形状校验）。
#[allow(dead_code)]
fn _assert_kdf_shape(k: KdfParams) -> KdfParams {
    k
}
