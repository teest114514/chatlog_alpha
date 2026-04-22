import asyncio
import json
import os
import sys
from pathlib import Path


def main() -> int:
    payload = json.load(sys.stdin)
    hermes_root = str(payload.get("hermes_root") or "").strip()
    if not hermes_root:
        raise RuntimeError("Hermes root missing")
    if hermes_root not in sys.path:
        sys.path.insert(0, hermes_root)

    from gateway.config import PlatformConfig
    from gateway.platforms.weixin import ContextTokenStore, WeixinAdapter, _make_ssl_connector
    import aiohttp

    async def run() -> dict:
        account_id = str(payload.get("account_id") or "").strip()
        token = str(payload.get("token") or "").strip()
        base_url = str(payload.get("base_url") or "").strip()
        cdn_base_url = str(payload.get("cdn_base_url") or "").strip()
        chat_id = str(payload.get("chat_id") or "").strip()
        text = str(payload.get("text") or "").strip()
        media_paths = [str(p).strip() for p in (payload.get("media_paths") or []) if str(p).strip()]
        hermes_home = str(payload.get("hermes_home") or os.getenv("HERMES_HOME") or "").strip()

        if not token:
            return {"success": False, "error": "Weixin token missing"}
        if not account_id:
            return {"success": False, "error": "Weixin account ID missing"}
        if not chat_id:
            return {"success": False, "error": "Weixin home channel missing"}

        token_store = ContextTokenStore(hermes_home)
        token_store.restore(account_id)

        async with aiohttp.ClientSession(trust_env=True, connector=_make_ssl_connector()) as session:
            adapter = WeixinAdapter(
                PlatformConfig(
                    enabled=True,
                    token=token,
                    extra={
                        "account_id": account_id,
                        "base_url": base_url,
                        "cdn_base_url": cdn_base_url,
                    },
                )
            )
            adapter._send_session = session
            adapter._session = session
            adapter._token = token
            adapter._account_id = account_id
            adapter._base_url = base_url
            adapter._cdn_base_url = cdn_base_url
            adapter._token_store = token_store

            send_text_first = text and not media_paths
            if send_text_first:
                result = await adapter.send(chat_id, text)
                if not result.success:
                    return {"success": False, "error": result.error or "weixin text send failed"}

            for index, media_path in enumerate(media_paths):
                caption = text if index == 0 else None
                suffix = Path(media_path).suffix.lower()
                if suffix in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}:
                    result = await adapter.send_image_file(chat_id, media_path, caption=caption)
                elif suffix in {".mp4", ".mov", ".m4v", ".avi", ".mkv"}:
                    result = await adapter.send_video(chat_id, media_path, caption=caption)
                elif suffix in {".silk", ".amr", ".wav", ".mp3", ".m4a", ".ogg"}:
                    result = await adapter.send_voice(chat_id, media_path, caption=caption)
                else:
                    result = await adapter.send_document(chat_id, media_path, caption=caption)
                if not result.success:
                    return {"success": False, "error": result.error or f"weixin media send failed: {media_path}"}

        return {"success": True}

    try:
        result = asyncio.run(run())
    except Exception as exc:
        result = {"success": False, "error": str(exc)}
    json.dump(result, sys.stdout, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
