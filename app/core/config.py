import os
import json
import logging
import base64
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional, Dict, Any

# 获取一个日志记录器实例
logger = logging.getLogger(__name__)

class AuthCookie:
    """
    处理并生成 Smithery.ai 所需的认证 Cookie。
    它将 .env 文件中的 JSON 字符串转换为一个标准的 HTTP Cookie 头部字符串。
    """
    def __init__(self, cookie_string: str):
        try:
            data = self._parse_cookie_string(cookie_string)
            self.access_token = data.get("access_token")
            self.refresh_token = data.get("refresh_token")
            self.expires_at = data.get("expires_at", 0)
            
            if not self.access_token:
                raise ValueError("Cookie JSON 中缺少 'access_token'")

            # 2. 构造将要放入 Cookie header 的值部分 (它本身也是一个 JSON)
            #    注意：这里我们只包含 Supabase auth 需要的核心字段
            cookie_value_data = {
                "access_token": self.access_token,
                "refresh_token": self.refresh_token,
                "token_type": data.get("token_type", "bearer"),
                "expires_in": data.get("expires_in", 3600),
                "expires_at": self.expires_at,
                "user": data.get("user")
            }
            
            # 3. 构造完整的 Cookie 键值对字符串
            #    Smithery.ai 使用的 Supabase project_ref 是 'spjawbfpwezjfmicopsl'
            project_ref = "spjawbfpwezjfmicopsl"
            cookie_key = f"sb-{project_ref}-auth-token"
            # 将值部分转换为紧凑的 JSON 字符串
            cookie_value = json.dumps(cookie_value_data, separators=(',', ':'))
            
            # 最终用于 HTTP Header 的字符串，格式为 "key=value"
            self.header_cookie_string = f"{cookie_key}={cookie_value}"

        except Exception as e:
            raise ValueError(f"初始化 AuthCookie 时出错: {e}")

    def __repr__(self):
        return f"<AuthCookie expires_at={self.expires_at}>"

    @staticmethod
    def _parse_cookie_string(raw_value: str) -> Dict[str, Any]:
        if raw_value is None:
            raise ValueError("提供的 cookie 字符串为空")

        stripped = raw_value.strip()
        if stripped and stripped[0] in {"'", '"'} and stripped[-1] == stripped[0]:
            # 某些环境（例如 .env 文件）会为值自动包裹引号
            stripped = stripped[1:-1].strip()
        if not stripped:
            raise ValueError("提供的 cookie 字符串为空")

        # 先尝试从完整的 Cookie 头部中提取 JSON（如: sb-<project>-auth-token={...}）
        try:
            if "-auth-token=" in stripped and "{" in stripped and "}" in stripped:
                # 只提取 '=' 之后到末尾（或到第一个分号）的部分
                kv = stripped.split("-auth-token=", 1)[1]
                kv = kv.split(";", 1)[0].strip()
                if kv and kv[0] in '{"' and kv[-1] in '}"':
                    # 去掉可能的包裹引号
                    if kv[0] == '"' and kv[-1] == '"':
                        kv = kv[1:-1]
                    parsed = json.loads(kv)
                    return parsed
        except Exception:
            # 提取失败则继续后续流程
            pass

        # 尝试直接解析 JSON（向后兼容旧配置）
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass

        def _looks_like_base64(text: str) -> bool:
            # 允许的字符集（含 URL-safe）
            allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")
            return all(ch in allowed or ch.isspace() for ch in text)

        def _try_parse_base64(text: str) -> Dict[str, Any]:
            # 去前缀 'base64-'（用户可能未去除，此处兼容）
            if text.lower().startswith("base64-"):
                text = text[7:]

            # 去除空白与不可见字符，并保留 base64/urlsafe 允许的字符
            text = "".join(text.split())
            cleaned = "".join(ch for ch in text if ch.isalnum() or ch in "+/=_-")
            if not cleaned:
                raise ValueError("base64 cookie 字符串为空")

            # 统计非 '=' 的数据字符数，用来判断是否明显被截断
            data_len = len(cleaned.replace("=", ""))
            if data_len % 4 == 1:
                # 这种情况属于不可修复的截断（无法通过补 '=' 修复）
                raise ValueError("疑似不完整的 base64：数据长度为 4n+1，请重新完整复制")

            # 自动补齐 '='（当余数为 2 或 3 时可补齐）
            if data_len % 4 in (2, 3):
                cleaned += "=" * (4 - (data_len % 4))

            # 先按标准 base64，再按 urlsafe 尝试
            decoded_bytes = None
            last_err = None
            for decoder in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    decoded_bytes = decoder(cleaned)
                    break
                except Exception as err:
                    last_err = err
                    decoded_bytes = None
            if decoded_bytes is None:
                raise ValueError("无法解析 base64 编码的 cookie 字符串") from last_err

            try:
                decoded = decoded_bytes.decode("utf-8")
            except Exception as err:
                raise ValueError("base64 解码后的内容不是有效的 UTF-8 字符串") from err

            try:
                return json.loads(decoded)
            except json.JSONDecodeError as json_err:
                raise ValueError("base64 解码后的内容不是有效的 JSON") from json_err

        # 优先尝试解析 base64（带或不带前缀），仅当字符串“看起来像 base64”时
        if _looks_like_base64(stripped):
            try:
                return _try_parse_base64(stripped)
            except ValueError as e:
                # 记录调试信息后继续最终回退错误
                logger.debug(f"base64 解析尝试失败: {e}")

        # 回退到直接解析 JSON（兼容原有配置）
        try:
            return json.loads(stripped)
        except json.JSONDecodeError as json_err:
            raise ValueError("提供的 cookie 字符串既不是可识别的 base64，也不是有效的 JSON") from json_err


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding='utf-8',
        extra="ignore"
    )

    APP_NAME: str = "smithery-2api"
    APP_VERSION: str = "1.0.0"
    DESCRIPTION: str = "一个将 smithery.ai 转换为兼容 OpenAI 格式 API 的高性能代理，支持多账号、上下文和工具调用。"

    CHAT_API_URL: str = "https://smithery.ai/api/chat"
    TOKEN_REFRESH_URL: str = "https://spjawbfpwezjfmicopsl.supabase.co/auth/v1/token?grant_type=refresh_token"
    SUPABASE_API_KEY: str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNwamF3YmZwd2V6amZtaWNvcHNsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MzQxNDc0MDUsImV4cCI6MjA0OTcyMzQwNX0.EBIg7_F2FZh4KZ3UNwZdBRjpp2fgHqXGJOvOSQ053MU"

    API_MASTER_KEY: Optional[str] = None
    
    AUTH_COOKIES: List[AuthCookie] = []

    API_REQUEST_TIMEOUT: int = 180
    NGINX_PORT: int = 8088
    SESSION_CACHE_TTL: int = 3600

    KNOWN_MODELS: List[str] = [
        "claude-haiku-4.5", "claude-sonnet-4.5", "gpt-5", "gpt-5-mini", 
        "gpt-5-nano", "gemini-2.5-flash-lite", "gemini-2.5-pro", "glm-4.6", 
        "grok-4-fast-non-reasoning", "grok-4-fast-reasoning", "kimi-k2", "deepseek-reasoner"
    ]

    def __init__(self, **values):
        super().__init__(**values)
        # 从环境变量 SMITHERY_COOKIE_1, SMITHERY_COOKIE_2, ... 加载 cookies
        i = 1
        while True:
            cookie_str = os.getenv(f"SMITHERY_COOKIE_{i}")
            if cookie_str:
                try:
                    # 使用 AuthCookie 类来解析和处理 cookie 字符串
                    self.AUTH_COOKIES.append(AuthCookie(cookie_str))
                except ValueError as e:
                    logger.warning(f"无法加载或解析 SMITHERY_COOKIE_{i}: {e}")
                i += 1
            else:
                break
        
        if not self.AUTH_COOKIES:
            raise ValueError("必须在 .env 文件中至少配置一个有效的 SMITHERY_COOKIE_1")

settings = Settings()
