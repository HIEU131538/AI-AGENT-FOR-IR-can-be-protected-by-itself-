"""
core/fields.py — B5.1 (AegisSOC): BẢNG TÊN TRƯỜNG TƯƠNG ĐƯƠNG

Cùng một thông tin, mỗi nguồn gọi một kiểu: Nginx `request_uri`, IIS/Sigma `cs-uri-stem` + `cs-uri-query`,
Splunk `cs_uri_query`, CIM `url`… Extractor và Retriever của lõi cũ chỉ biết tên kiểu Nginx, nên với bộ vàng v2
(tên kiểu IIS/Sigma) Retriever dựng câu truy vấn chỉ từ tên luật (7/7 alert web).

`canonical_fields(fields)` trả về các khoá CHUẨN còn thiếu, lấy giá trị từ tên tương đương. So khớp tên sau khi
bỏ ký tự không phải chữ/số và viết thường, nên `cs(User-Agent)`, `cs_User_Agent`, `cs-user-agent` là một.

Chỉ dùng cho các trạm TẤT ĐỊNH đọc raw_log (Extractor, Correlator, Retriever) qua `to_legacy_raw_log`.
Ticket (thứ LLM đọc) vẫn giữ `fields` NGUYÊN VĂN với tên gốc — không thêm, không đổi tên.
"""
import re
from typing import Any, Dict

_NORM = re.compile(r"[^a-z0-9]")


def _norm(key: str) -> str:
    return _NORM.sub("", str(key).lower())


# khoá chuẩn → các tên tương đương (đã chuẩn hoá bằng _norm). Tên chuẩn cũng nằm trong danh sách.
ALIASES = {
    "request_method":    {"requestmethod", "csmethod", "httpmethod", "method", "httprequestmethod"},
    "request_uri":       {"requesturi", "uri", "url", "requesturl", "csuri", "httpurl", "urioriginal"},
    "http_user_agent":   {"httpuseragent", "csuseragent", "useragent", "httphttpuseragent", "requestuseragent"},
    "request_body":      {"requestbody", "httprequestbody", "formdata", "postdata", "requestpostdata"},
    "status":            {"status", "scstatus", "httpstatus", "statuscode", "httpstatuscode"},
    "remote_addr":       {"remoteaddr", "cip", "clientip", "httpclientip"},
    "dns_query":         {"dnsquery", "queryname", "rrname", "dnsrrname", "dnsqueryname"},
    "CommandLine":       {"commandline", "processcommandline", "cmdline"},
    "Image":             {"image", "processpath", "newprocessname", "processimage"},
    "ParentImage":       {"parentimage", "parentprocesspath", "parentprocessname"},
    "ParentCommandLine": {"parentcommandline", "parentprocesscommandline"},
    "User":              {"user", "username", "subjectusername", "processuser"},
}
# URL tách hai phần (IIS/Sigma, Splunk): ghép lại thành request_uri = stem + "?" + query
_URI_STEM = {"csuristem", "uripath", "urlpath", "requestpath", "httpurlpath"}
_URI_QUERY = {"csuriquery", "uriquery", "querystring", "requestquery", "httpurlquery"}
_EMPTY = {None, "", "-"}


def _flatten(fields: Dict[str, Any], prefix: str = "", depth: int = 0) -> Dict[str, Any]:
    """Trải phẳng dict lồng (vd. Suricata `http.http_user_agent`, `dns.rrname`) — tối đa 3 tầng."""
    flat: Dict[str, Any] = {}
    for k, v in (fields or {}).items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict) and depth < 2:
            flat.update(_flatten(v, key, depth + 1))
        elif not isinstance(v, (list, dict)):
            flat[key] = v
    return flat


def _uri_from_parts(by_norm: Dict[str, Any]):
    stem = next((by_norm[n] for n in sorted(_URI_STEM) if n in by_norm), None)
    query = next((by_norm[n] for n in sorted(_URI_QUERY) if n in by_norm), None)
    q = "" if query is None else str(query)
    if q.startswith("/"):                  # một số nguồn ghi cả đường dẫn vào phần query
        return q
    if q:
        return f"{stem or ''}?{q.lstrip('?')}"
    return None if stem is None else str(stem)


def canonical_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    """Các khoá chuẩn CÒN THIẾU trong `fields`, lấy từ tên tương đương. Không bao giờ ghi đè khoá đã có."""
    fields = fields or {}
    by_norm: Dict[str, Any] = {}
    for k, v in _flatten(fields).items():
        if v in _EMPTY:
            continue
        # khoá lồng: thử cả tên đầy đủ (http.http_user_agent) lẫn tên lá (http_user_agent)
        for n in (_norm(k), _norm(k.rsplit(".", 1)[-1])):
            by_norm.setdefault(n, v)

    extra: Dict[str, Any] = {}
    for canon, names in ALIASES.items():
        if canon in fields:
            continue
        for n in sorted(names):
            if n in by_norm:
                extra[canon] = by_norm[n]
                break
    if "request_uri" not in extra and "request_uri" not in fields:
        uri = _uri_from_parts(by_norm)
        if uri is not None:
            extra["request_uri"] = uri
    return extra
