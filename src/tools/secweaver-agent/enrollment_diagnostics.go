package main

import (
	"errors"
	"net/http"

	"secweaver-agent/pkg/agentlicense"
)

type enrollmentDiagnostic struct {
	status int
	detail string
	hint   string
}

// This read-only allowlist is the presentation boundary: no server message,
// HTML response or unknown code becomes terminal text or a recovery command.
var enrollmentDiagnostics = map[string]enrollmentDiagnostic{
	"DeviceIdentityConflict": {
		http.StatusForbidden,
		"Local device identity was revoked, replaced or conflicts with its registered ownership/key. / 本机设备身份已被撤销、替换，或与登记的企业/密钥冲突。",
		"Ask the enterprise administrator to verify this device's registration and the intended reinstall procedure. Preserve local state and private key for diagnosis; do not delete identity to bypass rejection. / 请企业管理员核对设备记录及重装流程；保留本地状态和私钥用于排查，不要删除身份绕过拒绝。",
	},
	"DeviceQuotaExceeded": {
		http.StatusForbidden,
		"Enterprise device quota is full or exceeded. / 企业设备额度已满或超额。",
		"Revoke confirmed unused device registrations or ask the administrator to increase the device quota, then retry. Offline or uninstalled devices still occupy a slot until revoked; deleting local state does not release it. / 撤销确认不用的设备注册，或请管理员提高额度后重试；离线或卸载不释放额度，删除本地状态也不释放。",
	},
	"EnrollmentTokenExhausted": {
		http.StatusForbidden,
		"Enrollment token's cumulative registration limit is exhausted. / 安装令牌累计注册次数已用完，即使尚未到期也无法新增注册。",
		"Generate a new installation command in Data Cloud. Revoking a device does not restore this token's cumulative registration allowance. Preserve the existing device identity. / 请在 Data Cloud 生成新安装命令；撤销设备不会恢复此令牌的累计注册次数，请保留现有设备身份。",
	},
	"EnterpriseDisabled": {
		http.StatusForbidden,
		"Enterprise is disabled or not yet active. / 企业被禁用、尚未开通或尚未到生效时间。",
		"Ask the administrator to enable the enterprise or complete activation; replacing the installation token does not enable the enterprise. / 请管理员启用企业或完成开通；更换安装令牌不能解除企业禁用。",
	},
	"SubscriptionExpired": {
		http.StatusForbidden,
		"Enterprise subscription has expired. / 企业订阅已到期。",
		"Ask the administrator to renew the enterprise subscription, then retry enrollment. Replacing the installation token does not renew the subscription. / 请管理员续期企业授权后重试；更换安装令牌不能延长订阅。",
	},
	"AmbiguousReinstall": {
		http.StatusConflict,
		"Multiple active registrations match this host's hardware fingerprint. / 同一硬件指纹匹配到多个有效设备身份，无法确定替换对象。",
		"Ask the administrator to verify duplicate registrations before reinstalling. Do not automatically revoke devices or delete the local identity. / 请管理员先核对重复设备记录；不要自动撤销设备或删除本地身份。",
	},
	"RequestReplay": {
		http.StatusUnauthorized,
		"Enrollment request was already used. / 注册请求被识别为重复请求。",
		"Retry with the enroll command to create a fresh request; inspect proxy retries if it repeats. Preserve the device identity. / 使用 enroll 命令生成新请求重试；若仍重复，请检查代理重放，保留设备身份。",
	},
}

// enrollmentRejection trusts only fixed status/code pairs. Older JSON responses
// may provide reason/message, and legacy allowed=false responses use HTTP 200.
// Authentication remains deliberately ambiguous; a generic WAF 403 cannot
// establish quota exhaustion, subscription state or device ownership.
func enrollmentRejection(err error) (int, string, enrollmentDiagnostic, bool) {
	statusCode, code, legacyDenial := 0, "", false
	var status *agentlicense.HTTPStatusError
	var denied agentlicense.DeniedError
	switch {
	case errors.As(err, &status):
		statusCode, code = status.StatusCode, status.ErrorCode
		if code == "" {
			code = status.Reason
		}
	case errors.As(err, &denied):
		statusCode, code, legacyDenial = http.StatusOK, denied.Response.ErrorCode, true
		if code == "" {
			code = denied.Response.Reason
		}
		if code == "" {
			code = denied.Response.Message
		}
	default:
		return 0, "", enrollmentDiagnostic{}, false
	}
	if diagnostic, ok := enrollmentDiagnostics[code]; ok && (statusCode == diagnostic.status || legacyDenial) {
		return statusCode, code, diagnostic, true
	}
	diagnostic := enrollmentDiagnostic{status: statusCode, detail: http.StatusText(statusCode)}
	code = "UnknownRejection"
	switch statusCode {
	case http.StatusUnauthorized:
		if status.ErrorCode == "Unauthorized" || status.ErrorCode == "" && status.Reason == "Unauthorized" {
			code = "Unauthorized"
		}
		diagnostic.detail = "Enrollment authentication failed; the response does not identify which check failed. / 注册认证失败，响应未区分具体校验项。"
		diagnostic.hint = "Check the current installation command and host clock. The token may be invalid, expired or revoked, or request authentication may have failed. Preserve the device identity and TLS verification. / 核对当前安装命令和主机时间；可能是令牌无效、过期、撤销或请求认证失败，请保留设备身份和 TLS 校验。"
	case http.StatusNotFound:
		if status.ErrorCode == "NotFound" || status.ErrorCode == "" && status.Reason == "NotFound" {
			code = "NotFound"
		}
		diagnostic.hint = "Check the Agent Gateway origin and /api/secweaver/v2/agent/enroll route, including reverse-proxy configuration. A 404 does not indicate an expired token. / 请核对 Agent Gateway 地址和注册路由；404 不代表令牌过期。"
	case http.StatusForbidden:
		diagnostic.detail = "Enrollment was rejected without a recognized reason. / 注册被拒绝，但响应没有可识别的具体原因。"
		diagnostic.hint = "Check the Gateway response and WAF/reverse-proxy logs. HTTP 403 alone does not establish token expiry, device quota or identity conflict. / 请检查 Gateway 响应及 WAF/反向代理日志；仅凭 403 不能判断令牌过期、设备满额或身份冲突。"
	default:
		if legacyDenial {
			diagnostic.detail = "Enrollment was not allowed without a recognized reason. / 注册未获授权，响应没有可识别的具体原因。"
		}
	}
	return statusCode, code, diagnostic, true
}
