package acme

import "encoding/base64"

// b64u 是 RFC 8555 全文使用的 base64url（无填充）编码。
// 不引第三方库、不引 encoding/base64 之外的实现：ACME 的每个签名输入都要字节级可控。
func b64u(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

// b64uDecode 解码 base64url（无填充）。
func b64uDecode(raw string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(raw) }
