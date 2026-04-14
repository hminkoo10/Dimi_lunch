import json
import os
import base64
import binascii
import hashlib
import hmac
import struct
import sys
import tempfile
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote

import requests
from instagrapi import Client
from instagrapi.exceptions import ChallengeRequired, LoginRequired, TwoFactorRequired
from PIL import Image, ImageDraw, ImageFont

API_BASE_URL = "https://api.xn--rh3b.net"
API_HEADERS = {
    "Accept": "application/json,text/plain,*/*",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/123.0.0.0 Safari/537.36"
    ),
}
KST = timezone(timedelta(hours=9))
SCHOOL_NAME = "한국디지털미디어고등학교"

MEAL_LABELS = {
    "breakfast": "아침",
    "lunch": "점심",
    "dinner": "저녁",
}
SCHEDULE_TIMES = [
    ((6, 30), "breakfast"),
    ((8, 30), "lunch"),
    ((14, 30), "dinner"),
]
TEMPLATE_PATHS = {
    "breakfast": Path("./breakfast_template.png"),
    "lunch": Path("./lunch_template.png"),
    "dinner": Path("./dinner_template.png"),
}

FONT_PATH = Path("./MalangmalangR.ttf")
SECRET_PATH = Path("./secret.json")
STATE_PATH = Path("./upload_state.json")
SESSION_PATH = Path("./insta_session.json")
DATE_TOP_RATIO = 0.035
DATE_MAX_WIDTH_RATIO = 0.86
CONTENT_LEFT_RATIO = 0.10
CONTENT_RIGHT_RATIO = 0.90
CONTENT_TOP_RATIO = 0.265
CONTENT_BOTTOM_RATIO = 0.87


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def save_json(path: Path, data: dict):
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_state() -> dict[str, str]:
    if not STATE_PATH.exists():
        return {}

    try:
        data = load_json(STATE_PATH)
    except (OSError, json.JSONDecodeError):
        return {}

    if not isinstance(data, dict):
        return {}

    parsed: dict[str, str] = {}
    for key, value in data.items():
        if isinstance(key, str) and isinstance(value, str):
            parsed[key] = value
    return parsed


def save_state(state: dict[str, str]):
    save_json(STATE_PATH, state)


def normalize_two_factor_method(value: str | None) -> str:
    key = (value or "").strip().lower()
    mapping = {
        "": "prompt",
        "prompt": "prompt",
        "manual": "prompt",
        "totp": "totp",
        "app": "totp",
        "authenticator": "totp",
        "backup": "backup",
        "backup_code": "backup",
        "code": "code",
    }
    return mapping.get(key, "prompt")


def clean_code(value: str | None) -> str:
    return str(value or "").strip().replace(" ", "")


def generate_totp_code(secret: str, digits: int = 6, period: int = 30) -> str:
    normalized = clean_code(secret).replace("-", "").upper()
    key = base64.b32decode(normalized, casefold=True)
    counter = int(time.time() // period)
    message = struct.pack(">Q", counter)
    digest = hmac.new(key, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


def load_auth_config(auth_config: dict | None = None) -> dict:
    if isinstance(auth_config, dict):
        return auth_config
    if SECRET_PATH.exists():
        try:
            loaded = load_json(SECRET_PATH)
            if isinstance(loaded, dict):
                return loaded
        except Exception:
            pass
    return {}


def pop_backup_code(auth_config: dict) -> str | None:
    codes = auth_config.get("two_factor_backup_codes")
    if not isinstance(codes, list):
        return None

    while codes:
        code = clean_code(codes.pop(0))
        if code:
            auth_config["two_factor_backup_codes"] = codes
            try:
                save_json(SECRET_PATH, auth_config)
                print("[Instagram] 백업 코드 1개 사용 및 저장 완료")
            except Exception as exc:
                print(f"[Instagram] 백업 코드 목록 저장 실패: {exc}")
            return code
    return None


def get_two_factor_code(auth_config: dict | None = None) -> str:
    config = load_auth_config(auth_config)

    env_code = clean_code(os.getenv("INSTAGRAM_2FA_CODE"))
    if env_code:
        return env_code

    method = normalize_two_factor_method(
        os.getenv("INSTAGRAM_2FA_METHOD") or str(config.get("two_factor_method") or "")
    )

    if method == "totp":
        totp_secret = clean_code(
            os.getenv("INSTAGRAM_2FA_TOTP_SECRET") or config.get("two_factor_totp_secret")
        )
        if not totp_secret:
            print("[Instagram] two_factor_totp_secret가 없어 수동 입력으로 전환합니다.")
        else:
            try:
                return generate_totp_code(totp_secret)
            except (binascii.Error, ValueError) as exc:
                print(f"[Instagram] TOTP 생성 실패, 수동 입력으로 전환: {exc}")

    if method == "backup":
        backup_code = pop_backup_code(config)
        if backup_code:
            return backup_code
        print("[Instagram] 백업 코드가 비어 있어 수동 입력으로 전환합니다.")

    if method == "code":
        static_code = clean_code(str(config.get("two_factor_code") or ""))
        if static_code:
            return static_code
        print("[Instagram] two_factor_code가 비어 있어 수동 입력으로 전환합니다.")

    manual = clean_code(input("[Instagram] 2차 인증 코드를 입력하세요: "))
    if not manual:
        raise RuntimeError("2차 인증 코드가 입력되지 않았습니다.")
    return manual


def login_with_password(client: Client, insta_id: str, insta_pw: str, auth_config: dict | None = None):
    try:
        client.login(insta_id, insta_pw)
        return
    except TwoFactorRequired:
        code = get_two_factor_code(auth_config)
        client.login(insta_id, insta_pw, verification_code=code)


def register_two_factor_method():
    config = load_auth_config()

    print("[2FA 등록] 인증 수단을 선택하세요")
    print("1) 매번 수동 입력(prompt)")
    print("2) OTP 앱 비밀키(TOTP)")
    print("3) 백업 코드 목록")
    print("4) 고정 코드(테스트용)")
    print("5) 2FA 설정 초기화")
    choice = input("번호 입력: ").strip()

    if choice == "1":
        config["two_factor_method"] = "prompt"
        config.pop("two_factor_totp_secret", None)
        config.pop("two_factor_backup_codes", None)
        config.pop("two_factor_code", None)
    elif choice == "2":
        secret = clean_code(input("OTP 앱의 Base32 비밀키 입력: "))
        if not secret:
            raise ValueError("비밀키가 비어 있습니다.")
        config["two_factor_method"] = "totp"
        config["two_factor_totp_secret"] = secret
        config.pop("two_factor_backup_codes", None)
        config.pop("two_factor_code", None)
    elif choice == "3":
        print("백업 코드를 한 줄에 하나씩 입력하고, 빈 줄로 종료하세요.")
        codes: list[str] = []
        while True:
            line = clean_code(input("> "))
            if not line:
                break
            codes.append(line)
        if not codes:
            raise ValueError("백업 코드가 비어 있습니다.")
        config["two_factor_method"] = "backup"
        config["two_factor_backup_codes"] = codes
        config.pop("two_factor_totp_secret", None)
        config.pop("two_factor_code", None)
    elif choice == "4":
        code = clean_code(input("고정 2FA 코드 입력: "))
        if not code:
            raise ValueError("코드가 비어 있습니다.")
        config["two_factor_method"] = "code"
        config["two_factor_code"] = code
        config.pop("two_factor_totp_secret", None)
        config.pop("two_factor_backup_codes", None)
    elif choice == "5":
        config.pop("two_factor_method", None)
        config.pop("two_factor_totp_secret", None)
        config.pop("two_factor_backup_codes", None)
        config.pop("two_factor_code", None)
    else:
        raise ValueError("지원하지 않는 선택입니다.")

    save_json(SECRET_PATH, config)
    print("[2FA 등록] secret.json에 저장 완료")


def challenge_code_handler(username: str, choice):
    channel = "인증 수단"
    choice_text = str(choice).lower()
    if "sms" in choice_text:
        channel = "SMS"
    elif "email" in choice_text:
        channel = "이메일"

    code = input(f"[Instagram] {username} {channel} 인증코드를 입력하세요: ").strip()
    return code


def save_instagram_session(client: Client):
    try:
        client.dump_settings(str(SESSION_PATH))
        print(f"[Instagram] 세션 저장 완료: {SESSION_PATH}")
    except Exception as exc:
        print(f"[Instagram] 세션 저장 실패: {exc}")


def normalize_sessionid(value: str | None) -> str | None:
    if value is None:
        return None
    sessionid = str(value).strip()
    if not sessionid:
        return None
    if "%3a" in sessionid.lower():
        decoded = unquote(sessionid)
        if decoded:
            sessionid = decoded.strip()
    return sessionid


def verify_instagram_session(client: Client):
    last_error = None

    for check_name, check_fn in (
        ("account_info", client.account_info),
        ("timeline", client.get_timeline_feed),
    ):
        try:
            check_fn()
            return check_name
        except Exception as exc:
            last_error = exc
            print(f"[Instagram] 세션 검증({check_name}) 실패: {exc}")

    if last_error:
        raise last_error
    raise RuntimeError("Instagram 세션 검증에 실패했습니다.")


def try_manual_sessionid_login():
    manual = input("[Instagram] sessionid를 입력하면 재시도합니다. 없으면 엔터: ").strip()
    manual = normalize_sessionid(manual)
    if not manual or len(manual) <= 30:
        return None

    sid_client = Client()
    sid_client.challenge_code_handler = challenge_code_handler
    sid_client.login_by_sessionid(manual)
    check = verify_instagram_session(sid_client)
    save_instagram_session(sid_client)
    print(f"[Instagram] 수동 sessionid 로그인 완료 (검증: {check})")
    return sid_client


def build_instagram_client(
    insta_id: str | None,
    insta_pw: str | None,
    sessionid: str | None = None,
    auth_config: dict | None = None,
) -> Client:
    auth_config = load_auth_config(auth_config)
    sessionid = normalize_sessionid(sessionid)
    if not sessionid:
        env_sessionid = os.getenv("INSTAGRAM_SESSIONID")
        if env_sessionid:
            sessionid = normalize_sessionid(env_sessionid)

    client = Client()
    client.challenge_code_handler = challenge_code_handler

    if sessionid and len(sessionid) > 30:
        try:
            client.login_by_sessionid(sessionid)
            check = verify_instagram_session(client)
            print(f"[Instagram] sessionid로 로그인 완료 (검증: {check})")
            save_instagram_session(client)
            return client
        except Exception as exc:
            print(f"[Instagram] sessionid 로그인 실패, 다음 방법 시도: {exc}")

    if not insta_id or not insta_pw:
        raise ValueError(
            "sessionid 로그인에 실패했습니다. secret.json에 insta_id / insta_pw도 함께 넣어 주세요."
        )

    if SESSION_PATH.exists():
        try:
            client.load_settings(str(SESSION_PATH))
            check = verify_instagram_session(client)
            print(f"[Instagram] 저장된 세션으로 로그인 완료 (검증: {check})")
            save_instagram_session(client)
            return client
        except Exception as exc:
            print(f"[Instagram] 저장 세션 검증 실패, 비밀번호 로그인 시도: {exc}")
            try:
                login_with_password(client, insta_id, insta_pw, auth_config=auth_config)
                check = verify_instagram_session(client)
                print(f"[Instagram] 저장 세션 기반 재로그인 완료 (검증: {check})")
                save_instagram_session(client)
                return client
            except Exception as relogin_exc:
                print(f"[Instagram] 저장 세션 재로그인 실패, 새 로그인 시도: {relogin_exc}")

    try:
        login_with_password(client, insta_id, insta_pw, auth_config=auth_config)
        check = verify_instagram_session(client)
        print(f"[Instagram] 새 로그인 완료 (검증: {check})")
    except ChallengeRequired as exc:
        print("[Instagram] challenge_required 발생. 챌린지 해결을 시도합니다.")
        resolved = False
        last_json = getattr(client, "last_json", {}) or {}
        if isinstance(last_json, dict) and last_json.get("challenge"):
            try:
                resolved = bool(client.challenge_resolve(last_json))
            except Exception as resolve_exc:
                print(f"[Instagram] challenge_resolve 실패: {resolve_exc}")

        if resolved:
            print("[Instagram] 챌린지 해결 완료, 세션 검증 시도")
            try:
                check = verify_instagram_session(client)
                save_instagram_session(client)
                print(f"[Instagram] 챌린지 해결 후 세션 검증 완료 (검증: {check})")
                return client
            except Exception as verify_exc:
                cookie_sessionid = client.sessionid
                if cookie_sessionid and len(cookie_sessionid) > 30:
                    try:
                        sid_client = Client()
                        sid_client.challenge_code_handler = challenge_code_handler
                        sid_client.login_by_sessionid(cookie_sessionid)
                        check = verify_instagram_session(sid_client)
                        save_instagram_session(sid_client)
                        print(f"[Instagram] 챌린지 해결 쿠키(sessionid)로 로그인 완료 (검증: {check})")
                        return sid_client
                    except Exception as sid_exc:
                        raise RuntimeError(
                            "챌린지 해결 후 세션 검증 및 sessionid 재로그인 모두 실패했습니다. "
                            "인스타 앱에서 직접 로그인/인증 후 다시 시도해 주세요."
                        ) from sid_exc

                try:
                    manual_client = try_manual_sessionid_login()
                    if manual_client:
                        return manual_client
                except Exception as manual_exc:
                    raise RuntimeError(
                        "챌린지 해결 후 수동 sessionid 로그인도 실패했습니다. "
                        "인스타 앱에서 먼저 보안 확인을 완료해 주세요."
                    ) from manual_exc

                raise RuntimeError(
                    "챌린지 해결 후 세션 검증에 실패했습니다. "
                    "인스타 앱에서 직접 로그인/인증 후 다시 시도해 주세요."
                ) from verify_exc

        raise RuntimeError(
            "Instagram 보안 챌린지로 로그인에 실패했습니다. "
            "인스타 앱에서 본인인증을 먼저 완료하거나 secret.json에 sessionid를 추가해 주세요."
        ) from exc

    save_instagram_session(client)
    return client


def get_korean_day_name(target_date: date) -> str:
    days = ["월", "화", "수", "목", "금", "토", "일"]
    return days[target_date.weekday()]


def fetch_meal_payload(date_text: str) -> dict:
    url = f"{API_BASE_URL}/{date_text}"
    response = requests.get(url, headers=API_HEADERS, timeout=12)
    response.raise_for_status()
    payload = response.json()

    if not isinstance(payload, dict) or "data" not in payload:
        raise ValueError("급식 데이터가 응답에 없습니다.")

    return payload


def meal_text_from_payload(payload: dict, meal_key: str) -> str:
    meal_data = (payload.get("data", {}) or {}).get(meal_key, {}) or {}

    blocks: list[str] = []
    for title, key in (("일반식", "regular"), ("간편식", "simple"), ("추가", "plus")):
        items = [str(item).strip() for item in (meal_data.get(key, []) or []) if str(item).strip()]
        if not items:
            continue
        blocks.append(title)
        for item in items:
            blocks.append(f"- {item}")
        blocks.append("")

    if not blocks:
        return "급식 정보가 없습니다."

    if blocks[-1] == "":
        blocks.pop()
    return "\n".join(blocks)


def wrap_line(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.FreeTypeFont, max_width: int) -> list[str]:
    stripped = text.strip()
    if not stripped:
        return [""]

    wrapped: list[str] = []
    current = ""
    for char in stripped:
        candidate = current + char
        box = draw.textbbox((0, 0), candidate, font=font)
        width = box[2] - box[0]
        if width <= max_width or not current:
            current = candidate
            continue
        wrapped.append(current)
        current = char

    if current:
        wrapped.append(current)
    return wrapped


def text_size(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.FreeTypeFont) -> tuple[int, int]:
    box = draw.textbbox((0, 0), text, font=font)
    return box[2] - box[0], box[3] - box[1]


def truncate_to_width(
    draw: ImageDraw.ImageDraw,
    text: str,
    font: ImageFont.FreeTypeFont,
    max_width: int,
    suffix: str = "…",
) -> str:
    if text_size(draw, text, font)[0] <= max_width:
        return text

    current = text
    while current:
        candidate = current + suffix
        if text_size(draw, candidate, font)[0] <= max_width:
            return candidate
        current = current[:-1]
    return suffix


def fit_menu_lines(
    draw: ImageDraw.ImageDraw,
    text: str,
    max_width: int,
    max_height: int,
    max_font_size: int = 52,
    min_font_size: int = 14,
) -> tuple[ImageFont.FreeTypeFont, list[str], int]:
    raw_lines = text.splitlines()

    for font_size in range(max_font_size, min_font_size - 1, -1):
        font = ImageFont.truetype(str(FONT_PATH), font_size)
        wrapped_lines: list[str] = []
        for raw_line in raw_lines:
            wrapped_lines.extend(wrap_line(draw, raw_line, font, max_width))

        line_height = text_size(draw, "가", font)[1]
        line_spacing = max(8, int(font_size * 0.26))
        total_height = len(wrapped_lines) * line_height + (len(wrapped_lines) - 1) * line_spacing

        if total_height <= max_height:
            return font, wrapped_lines, line_spacing

    font = ImageFont.truetype(str(FONT_PATH), min_font_size)
    wrapped_lines = []
    for raw_line in raw_lines:
        wrapped_lines.extend(wrap_line(draw, raw_line, font, max_width))
    line_spacing = max(6, int(min_font_size * 0.2))
    line_height = text_size(draw, "가", font)[1]
    line_unit = line_height + line_spacing
    max_lines = max(1, (max_height + line_spacing) // line_unit)

    if len(wrapped_lines) > max_lines:
        wrapped_lines = wrapped_lines[:max_lines]
        wrapped_lines[-1] = truncate_to_width(draw, wrapped_lines[-1].rstrip(), font, max_width)

    return font, wrapped_lines, line_spacing


def fit_single_line_font(
    draw: ImageDraw.ImageDraw,
    text: str,
    max_width: int,
    max_font_size: int = 56,
    min_font_size: int = 28,
) -> ImageFont.FreeTypeFont:
    for font_size in range(max_font_size, min_font_size - 1, -1):
        font = ImageFont.truetype(str(FONT_PATH), font_size)
        if text_size(draw, text, font)[0] <= max_width:
            return font
    return ImageFont.truetype(str(FONT_PATH), min_font_size)


def create_meal_image(meal_text: str, meal_key: str, target_date: date) -> str:
    template_path = TEMPLATE_PATHS[meal_key]
    if not template_path.exists():
        raise FileNotFoundError(f"템플릿 파일이 없습니다: {template_path}")
    if not FONT_PATH.exists():
        raise FileNotFoundError(f"폰트 파일이 없습니다: {FONT_PATH}")

    template = Image.open(template_path).convert("RGB")
    image = template.copy()
    draw = ImageDraw.Draw(image)
    width, height = image.size

    day_name = get_korean_day_name(target_date)
    date_text = f"{target_date.strftime('%Y년 %m월 %d일')} ({day_name})"
    date_font = fit_single_line_font(
        draw=draw,
        text=date_text,
        max_width=int(width * DATE_MAX_WIDTH_RATIO),
    )
    date_w, date_h = text_size(draw, date_text, date_font)
    date_y = int(height * DATE_TOP_RATIO)
    draw.text(((width - date_w) / 2, date_y), date_text, fill=(0, 0, 0), font=date_font)

    content_left = int(width * CONTENT_LEFT_RATIO)
    content_right = int(width * CONTENT_RIGHT_RATIO)
    content_top = int(height * CONTENT_TOP_RATIO)
    content_bottom = int(height * CONTENT_BOTTOM_RATIO)
    max_content_width = content_right - content_left
    max_content_height = content_bottom - content_top

    body_font, wrapped_lines, line_spacing = fit_menu_lines(
        draw=draw,
        text=meal_text,
        max_width=max_content_width,
        max_height=max_content_height,
    )

    line_height = text_size(draw, "가", body_font)[1]
    total_body_height = len(wrapped_lines) * line_height + (len(wrapped_lines) - 1) * line_spacing
    y = content_top + max((max_content_height - total_body_height) // 2, 0)

    for line in wrapped_lines:
        line_width, _ = text_size(draw, line, body_font)
        x = content_left + (max_content_width - line_width) / 2
        if line:
            draw.text((x, y), line, fill=(0, 0, 0), font=body_font)
        y += line_height + line_spacing

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg")
    temp_path = temp_file.name
    temp_file.close()
    image.save(temp_path, format="JPEG", quality=95)
    return temp_path


def build_caption(meal_key: str, meal_text: str, target_date: date) -> str:
    meal_label = MEAL_LABELS[meal_key]
    date_text = target_date.strftime("%Y-%m-%d")
    hashtags = [
        "#한국디지털미디어고등학교",
        "#급식",
        f"#{meal_label}급식",
        "#디미고",
    ]
    caption = (
        f"[{date_text} {meal_label} 급식]\n"
        f"{meal_text}\n\n"
        + " ".join(hashtags)
    )
    return caption[:2200]


def upload_to_instagram(
    client: Client,
    image_path: str,
    caption: str,
    insta_id: str | None = None,
    insta_pw: str | None = None,
    sessionid: str | None = None,
    auth_config: dict | None = None,
) -> Client:
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"이미지 파일을 찾을 수 없습니다: {image_path}")

    with Image.open(image_path) as img:
        img.verify()

    sessionid = normalize_sessionid(sessionid)

    for attempt in range(2):
        try:
            client.photo_upload(image_path, caption=caption)
            try:
                client.photo_upload_to_story(image_path, caption="오늘 급식 확인해보세요!")
            except LoginRequired as story_exc:
                print(f"[Instagram] 스토리 업로드는 로그인 만료로 건너뜁니다: {story_exc}")
            save_instagram_session(client)
            return client
        except LoginRequired as upload_exc:
            if attempt == 0 and (sessionid or (insta_id and insta_pw)):
                print("[Instagram] media/configure login_required. 세션 재로그인 후 1회 재시도합니다.")
                client = build_instagram_client(
                    insta_id,
                    insta_pw,
                    sessionid=sessionid,
                    auth_config=auth_config,
                )
                continue
            raise RuntimeError(
                "Instagram 업로드 권한 세션이 아닙니다. 앱에서 보안 확인 후 새 sessionid로 다시 시도해 주세요."
            ) from upload_exc


def run_upload_for_meal(
    client: Client,
    state: dict[str, str],
    meal_key: str,
    target_date: date,
    insta_id: str | None = None,
    insta_pw: str | None = None,
    sessionid: str | None = None,
    auth_config: dict | None = None,
) -> Client:
    date_text = target_date.isoformat()
    if state.get(meal_key) == date_text:
        return client

    print(f"[Upload] {date_text} {meal_key} 업로드 시작")
    image_path = ""
    try:
        payload = fetch_meal_payload(date_text)
        meal_text = meal_text_from_payload(payload, meal_key)
        image_path = create_meal_image(meal_text, meal_key, target_date)
        caption = build_caption(meal_key, meal_text, target_date)
        client = upload_to_instagram(
            client,
            image_path,
            caption,
            insta_id=insta_id,
            insta_pw=insta_pw,
            sessionid=sessionid,
            auth_config=auth_config,
        )
        state[meal_key] = date_text
        save_state(state)
        print(f"[Upload] {date_text} {meal_key} 업로드 완료")
    except Exception as exc:
        print(f"[Upload] {date_text} {meal_key} 업로드 실패: {exc}")
    finally:
        if image_path and os.path.exists(image_path):
            try:
                os.remove(image_path)
            except OSError:
                pass
    return client


def start_scheduler(
    client: Client,
    insta_id: str | None = None,
    insta_pw: str | None = None,
    sessionid: str | None = None,
    auth_config: dict | None = None,
):
    state = load_state()
    print("[Scheduler] 시작됨. 업로드 시간: 06:30(아침), 08:30(점심), 14:30(저녁)")

    while True:
        now = datetime.now(KST)
        today = now.date()

        for (hour, minute), meal_key in SCHEDULE_TIMES:
            if now.hour == hour and now.minute == minute:
                client = run_upload_for_meal(
                    client,
                    state,
                    meal_key,
                    today,
                    insta_id=insta_id,
                    insta_pw=insta_pw,
                    sessionid=sessionid,
                    auth_config=auth_config,
                )

        time.sleep(20)


def test_once(meal_key: str = "lunch", date_text: str | None = None, upload: bool = False) -> str:
    if meal_key not in MEAL_LABELS:
        raise ValueError(f"meal_key는 breakfast/lunch/dinner 중 하나여야 합니다: {meal_key}")

    if date_text is None:
        target_date = datetime.now(KST).date()
        date_text = target_date.isoformat()
    else:
        target_date = datetime.strptime(date_text, "%Y-%m-%d").date()

    payload = fetch_meal_payload(date_text)
    meal_text = meal_text_from_payload(payload, meal_key)
    image_path = create_meal_image(meal_text, meal_key, target_date)
    print(f"[Test] 이미지 생성 완료: {image_path}")

    if upload:
        if not SECRET_PATH.exists():
            raise FileNotFoundError(f"secret.json 파일이 없습니다: {SECRET_PATH}")

        secret = load_json(SECRET_PATH)
        insta_id = secret.get("insta_id")
        insta_pw = secret.get("insta_pw")
        sessionid = normalize_sessionid(secret.get("sessionid"))
        if not sessionid and (not insta_id or not insta_pw):
            raise ValueError("secret.json에 sessionid 또는 insta_id / insta_pw 값이 필요합니다.")

        client = build_instagram_client(
            insta_id,
            insta_pw,
            sessionid=sessionid,
            auth_config=secret,
        )
        caption = build_caption(meal_key, meal_text, target_date)
        upload_to_instagram(
            client,
            image_path,
            caption,
            insta_id=insta_id,
            insta_pw=insta_pw,
            sessionid=sessionid,
            auth_config=secret,
        )
        print("[Test] 인스타그램 업로드 완료")

    return image_path


def main():
    if not SECRET_PATH.exists():
        raise FileNotFoundError(f"secret.json 파일이 없습니다: {SECRET_PATH}")

    secret = load_json(SECRET_PATH)
    insta_id = secret.get("insta_id")
    insta_pw = secret.get("insta_pw")
    sessionid = normalize_sessionid(secret.get("sessionid"))

    if not sessionid and (not insta_id or not insta_pw):
        raise ValueError("secret.json에 sessionid 또는 insta_id / insta_pw 값이 필요합니다.")

    client = build_instagram_client(
        insta_id,
        insta_pw,
        sessionid=sessionid,
        auth_config=secret,
    )

    start_scheduler(
        client,
        insta_id=insta_id,
        insta_pw=insta_pw,
        sessionid=sessionid,
        auth_config=secret,
    )


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in {"register-2fa", "--register-2fa"}:
        register_two_factor_method()
    else:
        main()
