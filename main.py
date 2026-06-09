import discord
from discord.ext import commands, tasks
from discord import app_commands
from discord import Webhook
import asyncio
import sqlite3
import time
import datetime 
from datetime import timezone, timedelta, time as dt_time
time_module = time 

import unicodedata # on_message 内で使用している場合
import json
from pathlib import Path
import string
import random
import hashlib
import aiohttp
import logging
import os
import re
import typing
import traceback
import uuid
import unicodedata
import io
from collections import defaultdict
import sys
import yarl

ADMIN_USER_ID = {
    1413790671407681676
}
WEBHOOK_URL = os.getenv("SECURITY_WEBHOOK_URL")  # 環境変数推奨
LOG_FILE = Path("data/user_logs.json")
LOG_FILE.parent.mkdir(exist_ok=True)
CURRENT_TERMS_VERSION = 1
# 不正アクセス（ツール）検知時の優しいメッセージ
ERROR_BOT_DETECTED = "⚠️ 通信環境の影響で認証に失敗しました。お手数ですが、もう一度画面上の操作をやり直してください。"
# タイポスクワッティング判定用の正解リスト
OFFICIAL_DOMAINS = ["discord.com", "discord.gg", "google.com", "google.co.jp", "youtube.com", "crowdworks.jp"]
# 明示的なブラックリスト
HARD_BLACKLIST = ["rt-bot.com", "doogle.gg", "doublecounter.gg"]
SUPPORT_GUILD_ID = 1460072359305154700
SUPPORT_LINK = "https://discord.gg/aBZSVxBpV5"
DEFAULT_COLOR = 0x00bfff  # 指定の水色
MODERATION_SERVER_ID = 1470994567485591564

DANGEROUS_PERMS = {
    "administrator": "サーバーの全操作が可能になり、場合によってはサーバーを崩壊できてしまいます",
    "manage_guild": "サーバー設定を改変される可能性があります",
    "manage_roles": "ロールを削除、管理、作成できてしまいます",
    "manage_channels": "チャンネルを削除したり、追加することができてしまいます",
    "kick_members": "勝手にメンバーを追放できてしまいます",
    "ban_members": "勝手にメンバーをBanできてしまいます",
    "manage_webhooks": "Webhook悪用で荒らしが可能になってしまいます",
    "view_audit_log": "監査ログから管理操作を把握できてしまいます",
    "manage_expressions": "スタンプや表現を改変できてしまいます",
    "manage_emojis": "絵文字を勝手に改変、削除できてしまいます",
    "mention_everyone": "@everyone で全体メンション、荒らしが可能になってしまいます",
    "manage_messages": "送信したメッセージを削除できてしまいます",
    "moderate_members": "他のユーザーをタイムアウトできてしまいます",
    "manage_threads": "勝手にスレッドを削除、管理できてしまいます",
    "manage_permissions": "ロールの権限を勝手に変更できてしまいます",
    "use_external_apps": "外部アプリを使用したスパムが可能になってしまいます",
    "manage_events": "現在のイベントを勝手に変更、削除できてしまいます",
    "manage_nicknames": "他のユーザーのニックネームを勝手に変更できてしまいます",
    "manage_guild_expressions": "サーバー表現を変更できます",
    "bypass_slowmode": "低速モードを無視してメッセージを送信できてしまいます"
}

# ===== サポート鯖 ニュースチャンネルID =====
SUPPORT_NEWS_CHANNEL_IDS = {
    "お知らせ": 1460087495420280956,   # お知らせ用ニュースチャンネル
    "変更ログ": 1460089031697108992,   # 変更ログ用ニュースチャンネル
}
# ===============================
# Intents（最小＋将来拡張OK）
# ===============================
intents = discord.Intents.default()
intents.message_content = True
intents.messages = True
intents.guilds = True
intents.members = True          
intents.moderation = True

# ===============================
# Bot 定義
# ===============================
bot = commands.AutoShardedBot(command_prefix="!", intents=intents)

# ===============================
# DataBase
# ===============================
# ==========================================
# データベース接続設定 (同時書き込み強化)
# ==========================================
# timeoutを30秒に設定し、WALモードを有効化することで
# 大規模サーバーでのAntiNuke同時処理を安定させます。
conn = sqlite3.connect("ban.db", check_same_thread=False, timeout=30.0)
cur = conn.cursor()

# WALモードと同期設定の最適化
cur.execute("PRAGMA journal_mode=WAL;")
cur.execute("PRAGMA synchronous=NORMAL;")

# -------------------------------
# temp bans
# -------------------------------
cur.execute("""
CREATE TABLE IF NOT EXISTS temp_bans (
    user_id INTEGER,
    guild_id INTEGER,
    unban_time INTEGER,
    reason TEXT,
    PRIMARY KEY (user_id, guild_id)
)
""")

# -------------------------------
# audit log channel
# -------------------------------
cur.execute("""
CREATE TABLE IF NOT EXISTS audit_log_channel (
    guild_id INTEGER PRIMARY KEY,
    channel_id INTEGER
)
""")

# -------------------------------
# bot blacklist
# -------------------------------
cur.execute("""
CREATE TABLE IF NOT EXISTS bot_blacklist (
    bot_id INTEGER PRIMARY KEY
)
""")

# -------------------------------
# antinuke enable flag
# -------------------------------
cur.execute("""
CREATE TABLE IF NOT EXISTS antinuke_bot (
    guild_id INTEGER PRIMARY KEY,
    enabled INTEGER DEFAULT 0
)
""")

# -------------------------------
# antinuke trigger state
# -------------------------------
cur.execute("""
CREATE TABLE IF NOT EXISTS antinuke_state (
    guild_id INTEGER PRIMARY KEY,
    triggered INTEGER DEFAULT 0
)
""")

# -------------------------------
# antinuke channel backup
# -------------------------------
cur.execute("""
CREATE TABLE IF NOT EXISTS antinuke_backup (
    guild_id INTEGER,
    channel_id INTEGER,
    role_id INTEGER,
    allow_send INTEGER
)
""")

# -------------------------------
# role backup（restore_roles / backup_roles 用）
# -------------------------------
cur.execute("""
CREATE TABLE IF NOT EXISTS role_backup (
    guild_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    role_name TEXT NOT NULL,
    permissions INTEGER NOT NULL,
    color INTEGER NOT NULL,
    hoist INTEGER NOT NULL,
    mentionable INTEGER NOT NULL,
    PRIMARY KEY (guild_id, role_id)
)
""")

# -------------------------------
# channel delete log（AntiNuke 判定用）
# -------------------------------
cur.execute("""
CREATE TABLE IF NOT EXISTS channel_delete_log (
    guild_id INTEGER,
    deleted_at INTEGER
)
""")

# -------------------------------
# invite freeze state（将来拡張）
# -------------------------------
cur.execute("""
CREATE TABLE IF NOT EXISTS antinuke_invite_state (
    guild_id INTEGER PRIMARY KEY,
    frozen INTEGER DEFAULT 0
)
""")

conn.commit()

# -------------------------------
# whitelist users
# -------------------------------
cur.execute("""
CREATE TABLE IF NOT EXISTS whitelist_users (
    guild_id INTEGER,
    user_id INTEGER,
    PRIMARY KEY (guild_id, user_id)
)
""")

# -------------------------------
# whitelist roles
# -------------------------------
cur.execute("""
CREATE TABLE IF NOT EXISTS whitelist_roles (
    guild_id INTEGER,
    role_id INTEGER,
    PRIMARY KEY (guild_id, role_id)
)
""")

conn.commit()

# -------------------------------
# antinuke role create counter
# -------------------------------
cur.execute("""
CREATE TABLE IF NOT EXISTS antinuke_role_counter (
    guild_id INTEGER PRIMARY KEY,
    created_count INTEGER,
    last_updated INTEGER
)
""")

conn.commit()

# -------------------------------
# antinuke channel delete counter
# -------------------------------
cur.execute("""
CREATE TABLE IF NOT EXISTS antinuke_channel_counter (
    guild_id INTEGER PRIMARY KEY,
    deleted_count INTEGER,
    last_updated INTEGER
)
""")
conn.commit()

# -------------------------------
# antispam enable flag
# -------------------------------
cur.execute("""
CREATE TABLE IF NOT EXISTS antispam_state (
    guild_id INTEGER PRIMARY KEY,
    enabled INTEGER DEFAULT 0
)
""")

# -------------------------------
# antispam message tracker
# -------------------------------
cur.execute("""
CREATE TABLE IF NOT EXISTS antispam_message_log (
    guild_id INTEGER,
    user_id INTEGER,
    content TEXT,
    timestamp INTEGER
)
""")

conn.commit()

# ===============================
# Perm Guard 設定
# ===============================
cur.execute("""
CREATE TABLE IF NOT EXISTS perm_guard (
    guild_id INTEGER PRIMARY KEY,
    enabled INTEGER,
    quarantine_role_id INTEGER
)
""")

conn.commit()

# ===============================
# Alert Mode（警戒モード）
# ===============================
cur.execute("""
CREATE TABLE IF NOT EXISTS alert_mode (
    guild_id INTEGER PRIMARY KEY,
    level TEXT NOT NULL CHECK(level IN ('low','medium','high'))
)
""")
conn.commit()

# ===============================
# Admin penalty（利用停止）
# ===============================
cur.execute("""
CREATE TABLE IF NOT EXISTS admin_penalties (
    user_id INTEGER PRIMARY KEY,
    until INTEGER,
    reason TEXT
)
""")

conn.commit()

# ===============================
# report 設定用DB
# ===============================
cur.execute("""
CREATE TABLE IF NOT EXISTS report_log_channel (
    guild_id INTEGER PRIMARY KEY,
    channel_id INTEGER NOT NULL
)
""")
conn.commit()

cur.execute("""
CREATE TABLE IF NOT EXISTS backups (
    backup_key TEXT PRIMARY KEY,
    owner_user_id INTEGER NOT NULL,
    source_guild_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    data TEXT NOT NULL
)
""")
conn.commit()

# -------------------------------
# image blacklist
# -------------------------------
cur.execute("""
CREATE TABLE IF NOT EXISTS image_blacklist (
    image_hash TEXT PRIMARY KEY,
    added_by INTEGER,
    added_at INTEGER
)
""")
conn.commit()

# ===============================
# Invite SafeMode
# ===============================
cur.execute("""
CREATE TABLE IF NOT EXISTS invite_safemode (
    guild_id INTEGER PRIMARY KEY,
    enabled INTEGER DEFAULT 0
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS invite_create_log (
    guild_id INTEGER,
    user_id INTEGER,
    created_at INTEGER
)
""")

conn.commit()

cur.execute(
    """
    CREATE TABLE IF NOT EXISTS antinuke_channel_user_counter (
        guild_id INTEGER,
        user_id INTEGER,
        deleted_count INTEGER,
        last_updated INTEGER,
        PRIMARY KEY (guild_id, user_id)
    )
    """
)
conn.commit()

cur.execute("""
CREATE TABLE IF NOT EXISTS terms_agreed (
    user_id INTEGER PRIMARY KEY,
    version INTEGER
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS terms_current (
    version INTEGER
)
""")

# 初期バージョン
cur.execute("SELECT version FROM terms_current")
if not cur.fetchone():
    cur.execute("INSERT INTO terms_current VALUES (1)")

conn.commit()

cur.execute("CREATE TABLE IF NOT EXISTS server_bl (id INTEGER PRIMARY KEY, expiry TEXT)")
conn.commit()

# 1. 認証パネルの設定保存用
cur.execute('''
    CREATE TABLE IF NOT EXISTS auth_settings (
        guild_id INTEGER PRIMARY KEY,
        auth_type TEXT,
        role_id INTEGER
    )
''')

# 2. 認証成功ログ用
cur.execute('''
    CREATE TABLE IF NOT EXISTS auth_logs (
        guild_id INTEGER,
        user_id INTEGER,
        auth_type TEXT,
        executed_at TIMESTAMP DEFAULT (DATETIME('now', 'localtime')),
        PRIMARY KEY (guild_id, user_id)
    )
''')
conn.commit()

cur.execute(
    """
    CREATE TABLE IF NOT EXISTS announce_channels (
        guild_id INTEGER,
        channel_id INTEGER,
        type TEXT,
        PRIMARY KEY (guild_id, type)
    )
    """
)
conn.commit()

# データベースに設定用テーブルを追加
cur.execute("""
CREATE TABLE IF NOT EXISTS antiphishing_state (
    guild_id INTEGER PRIMARY KEY,
    enabled INTEGER DEFAULT 0
)
""")
conn.commit()

JST = datetime.timezone(datetime.timedelta(hours=9))
cur.execute("""
    CREATE TABLE IF NOT EXISTS security_settings (
        guild_id INTEGER PRIMARY KEY,
        channel_id INTEGER,
        webhook_url TEXT
    )
""")
cur.execute("""
    CREATE TABLE IF NOT EXISTS daily_incidents (
        guild_id INTEGER,
        event_type TEXT,
        timestamp DATETIME
    )
""")
conn.commit()

# データベース初期化時に実行するコード
cur.execute("""
    CREATE TABLE IF NOT EXISTS antiraid_settings (
        guild_id INTEGER PRIMARY KEY,
        enabled INTEGER DEFAULT 0
    )
""")

# (任意) RAID検知履歴を統計として残すためのテーブル
cur.execute("""
    CREATE TABLE IF NOT EXISTS antiraid_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER,
        event_type TEXT,
        member_count INTEGER,
        timestamp DATETIME
    )
""")

conn.commit()

# ===============================
# Utils
# ===============================
def parse_duration(duration: str):
    if not duration:
        return None

    duration = duration.lower().strip()

    try:
        num_str = "".join(filter(str.isdigit, duration))
        unit = "".join(filter(str.isalpha, duration))

        if not num_str:
            return None

        num = int(num_str)

        # ===== 異常な巨大数防止 =====
        if num < 0 or num > 10_000_000:
            return None

        if unit in ["s", "sec", "second", "seconds"]:
            return num
        if unit in ["m", "min", "minute", "minutes"]:
            return num * 60
        if unit in ["h", "hour", "hours"]:
            return num * 3600
        if unit in ["d", "day", "days"]:
            return num * 86400

    except:
        return None

    return None

def is_whitelisted_member(member: discord.Member) -> bool:
    # HIGH 警戒時はホワイトリスト無視
    alert = get_alert_mode(member.guild)
    if alert == "high":
        return False

    # ユーザー whitelist
    cur.execute(
        "SELECT 1 FROM whitelist_users WHERE guild_id=? AND user_id=?",
        (member.guild.id, member.id)
    )
    if cur.fetchone():
        return True

    # ロール whitelist
    for role in member.roles:
        cur.execute(
            "SELECT 1 FROM whitelist_roles WHERE guild_id=? AND role_id=?",
            (member.guild.id, role.id)
        )
        if cur.fetchone():
            return True

    return False

def is_dangerous_role(role: discord.Role) -> bool:
    perms = role.permissions
    return any([
        perms.administrator,
        perms.manage_guild,
        perms.manage_roles,
        perms.manage_channels,
        perms.ban_members,
        perms.kick_members
    ])

def get_alert_mode(guild: discord.Guild) -> str:
    if guild is None:
        return "medium"

    try:
        cur.execute(
            "SELECT level FROM alert_mode WHERE guild_id=?",
            (guild.id,)
        )
        row = cur.fetchone()
        if row and row[0] in ("low", "medium", "high"):
            return row[0]
    except:
        pass

    return "medium"

def build_alert_mode_embed(current: str) -> discord.Embed:
    emoji = {
        "low": "🟢",
        "medium": "🟡",
        "high": "🔴"
    }

    embed = discord.Embed(
        title="🚨 警戒モード設定",
        description=(
            "**現在の警戒モード:** "
            f"{emoji[current]} **{current.upper()}**\n\n"
            "### 🟢 LOW（低）\n"
            "・誤検知を最小限に\n"
            "・通常運用向け\n\n"
            "### 🟡 MEDIUM（中）\n"
            "・標準設定（推奨）\n"
            "・荒らし検知と安定性のバランス\n\n"
            "### 🔴 HIGH（高）\n"
            "・**ホワイトリスト無視**\n"
            "・即BAN / 即AntiNuke\n"
            "・荒らし発生中向け\n\n"
            "⚠️ HIGHは一時的な使用を推奨"
        ),
        color=discord.Color.red()
    )

    return embed

def log_user_action(
    *,
    guild_id: int,
    action: str,
    executor_id: int | None = None,
    target_id: int | None = None,
    extra: dict | None = None
):
    entry = {
        "timestamp": int(time.time()),
        "guild_id": guild_id,
        "action": action,
        "executor_id": executor_id,
        "target_id": target_id,
        "extra": extra or {}
    }

    try:
        if LOG_FILE.exists():
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = []

        data.append(entry)
        data = data[-1000:]

        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    except Exception:
        pass

def is_admin_user(interaction: discord.Interaction) -> bool:
    return interaction.user.id == ADMIN_USER_ID

# ===============================
# バックアップキー生成
# ===============================
def generate_backup_key():
    chars = string.ascii_uppercase + string.digits
    return "-".join(
        "".join(random.SystemRandom().choice(chars) for _ in range(4))
        for _ in range(5)
    )

def hash_image_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# ===============================
# ランダム名判定（企業レベル）
# ===============================
def looks_random(name: str, user_id: int = None, owner_id: int = None) -> bool:
    """
    サーバー所有者を完全除外。普通の名前（gohan21235等）の誤検知を極限まで抑え、
    乗っ取りスパム垢（超長文ランダム名、人名+4桁数字）のみを的確に検出する完全版。
    """
    try:
        if not name:
            return False

        # 1. サーバー所有者（オーナー）は絶対に検知対象外（安全弁）
        if user_id and owner_id and user_id == owner_id:
            return False

        name = name.strip()
        length = len(name)

        # 短すぎる名前はスパム率が低いため除外
        if length < 6:
            return False

        # ===== 英数字・アンダースコアのみの判定 =====
        if re.fullmatch(r"[A-Za-z0-9_]+", name):
            
            # 【対策A】gohan21235 などの「名前＋長めの数字」を救済
            # 単に数字が連続しているだけ（例: 21235）なら、文字数全体に対して数字が多すぎない限り許容する。
            # ただし、末尾4桁数字かつ全体が「人名風で異様に長い」スパムは後述のロジックで仕留める。
            
            # ① 母音（aeiou）が1文字も含まれない → 高確率でランダム生成
            if not re.search(r"[aeiouAEIOU]", name):
                return True

            # ② 同一文字の5連続以上（aaaaaa等）
            if re.search(r"(.)\1{4,}", name):
                return True

            # ③ 英数字が激しく混ざり合うカオス度（Entropy）の検知
            # vm1wr2ix... のような文字と数字が細かく交互に出るタイプを捕まえる
            # 英字から数字、または数字から英字への切り替わり回数をカウント
            transitions = sum(1 for i in range(length - 1) if name[i].isalpha() != name[i+1].isalpha())
            if length >= 20 and transitions >= 8:
                return True

            # ④ 子音の異常な連続（w, y を除外した純粋な子音で判定）
            # スパム特有の「gzfprd」のような詰まった文字列を検知（しきい値を6文字に緩和して誤検知防止）
            if re.search(r"[bcdfghjklmnpqrstvxz]{6,}", name, re.I):
                return True

            # ⑤ 【ターゲット検知】乗っ取りスパムに多い「人名風ロング名 ＋ 末尾4桁数字」
            # 例: rhondaramirez0290 (19文字)
            # 全体が15文字以上と長く、末尾が「ちょうど4桁の数字」で終わる。かつ、数字の比率が多すぎないもの
            if length >= 15 and re.search(r'(?<!\d)\d{4}$', name):
                # 一般人の「gohan2004」などの短い名前は上の length>=15 で弾かれるため安全
                return True

            # ⑥ 完全に数字だけのアカウント（Botの自動生成に多い）
            if name.isdigit() and length >= 8:
                return True

        # ===== Unicode荒らし・記号系スパム =====
        # 不可視文字や特殊記号が文字数の60%を超えている場合
        if sum(not c.isalnum() for c in name) / length > 0.6:
            return True

        return False

    except Exception:
        return False


# ===============================
# 初期アイコン判定（企業レベル）
# ===============================
def is_default_avatar(member: discord.Member) -> bool:
    """
    デフォルトアイコンかどうか
    Discord仕様変更にも強い
    """

    try:
        if member is None:
            return False

        # avatar が None → デフォルト
        if member.avatar is None:
            return True

        # display_avatar が default_avatar と同一
        if member.display_avatar == member.default_avatar:
            return True

        return False

    except Exception:
        return False


# ===============================
# 非活動日数（企業レベル）
# ===============================
def inactive_days(member: discord.Member) -> int:
    """
    非活動の推定日数
    presence非公開でも安全に動作
    """

    try:
        if member is None:
            return 9999

        now = discord.utils.utcnow()

        # ===== Botは対象外（必要なら削除可）=====
        if member.bot:
            return 0

        # ===== アクティビティあり → 活動中 =====
        if getattr(member, "activities", None):
            if len(member.activities) > 0:
                return 0

        # ===== ステータスがオンライン系 =====
        if getattr(member, "status", None) in (
            discord.Status.online,
            discord.Status.idle,
            discord.Status.dnd,
        ):
            return 0

        # ===== 参加日ベース推定 =====
        if member.joined_at:
            days = (now - member.joined_at).days

            # 異常値防止
            if days < 0:
                return 0

            # 上限（安全）
            return min(days, 3650)  # 最大10年

        return 9999

    except Exception:
        return 9999

def create_terms_embed():

    embed = discord.Embed(
        title="利用規約が変更されています",
        description=(
            "利用規約が変更されたため、新しい利用規約への同意をお願いします。\n\n"
            "同意ボタンを押し利用を継続した場合、"
            "変更後の利用規約に同意されたものとみなします。"
        ),
        color=0xffcc00
    )

    return embed

def save_bl(g_id: int, expiry: typing.Optional[datetime.datetime]):
    # expiry は datetime オブジェクト、または None
    exp_str = expiry.isoformat() if expiry else "PERMANENT"
    cur.execute("INSERT OR REPLACE INTO server_bl VALUES (?, ?)", (g_id, exp_str))
    conn.commit() # 指定通り conn を使用

def is_blacklisted(g_id: int) -> bool:
    cur.execute("SELECT expiry FROM server_bl WHERE id = ?", (g_id,))
    row = cur.fetchone()
    if not row: return False
    if row[0] == "PERMANENT": return True
    # 期限切れチェック
    expiry = datetime.datetime.fromisoformat(row[0])
    if datetime.datetime.now(datetime.timezone.utc) > expiry:
        cur.execute("DELETE FROM server_bl WHERE id = ?", (g_id,))
        conn.commit()
        return False
    return True

def levenshtein_distance(s1, s2):
    """2つの文字列の似ている度合いを計算"""
    if len(s1) < len(s2): return levenshtein_distance(s2, s1)
    if len(s2) == 0: return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def is_scam_text(text):
    """文章のニュアンスから詐欺を判定（スコアリング制）"""
    score = 0
    text = text.lower()
    # 危険ワード
    if any(w in text for w in ["girl", "sex", "cam", "leaks", "nude", "sugar"]): score += 20
    if "free nitro" in text: score += 25
    if any(w in text for w in ["外国人", "アクセスを許可", "利益を分かち合う", "金銭より信用"]): score += 25
    if "crowdworks" in text and "アカウント" in text: score += 15
    return score >= 30

def is_advanced_scam_detection(text: str) -> tuple[bool, str]:
    """
    検知率を極限まで高めた詐欺検知エンジン。
    文脈・単語・外部誘導の3要素をクロスチェックします。
    """
    # 1. 外部誘導キーワード (検知逃れ対策済み)
    # t.me, telegram, ﾃﾚｸﾞﾗﾑ, ライン, 招待コード 等
    has_external_contact = re.search(
        r'(l[i|1|!]n[e|3]|ライン|らin|てれぐらむ|telegram|t\.me|連絡用|追加して|公式[a-z]|招待コード)', 
        text, re.IGNORECASE
    )

    # 2. カテゴリ別キーワード群
    # 仕事・プラットフォーム
    work_keywords = [
        'クラウド', '働', '副業', '案件', '仕事', '求人', '内職', '闇バイト'
    ]
    # 募集・勧誘
    recruit_keywords = [
        '募集', '募り', '探して', '一緒に', '担当', '協力'
    ]
    # 難易度・手軽さ
    easy_keywords = [
        '簡単', 'コピペ', 'ポチポチ', 'スマホ1つ', '誰でも', '初心者', '即金'
    ]
    # 信頼・金銭アピール
    scam_hooks = [
        '信用を優先', '金銭より', '稼げ', '報酬', '月収', '日払い', 'お小遣い'
    ]

    # カウント処理
    work_score = sum(1 for k in work_keywords if k in text)
    recruit_score = sum(1 for k in recruit_keywords if k in text)
    easy_score = sum(1 for k in easy_keywords if k in text)
    hook_score = sum(1 for k in scam_hooks if k in text)

    # ==================================================
    # 強制検知ロジック (コンボ判定)
    # ==================================================
    
    # パターンA: クラウド系求人募集 ＋ 外部誘導 (今回のケース)
    if (work_score >= 1 or hook_score >= 1) and recruit_score >= 1 and has_external_contact:
        return True, "クラウドワークス詐欺・外部誘導(コンボA検知)"

    # パターンB: 簡単作業 ＋ 報酬示唆 ＋ 外部誘導
    if easy_score >= 1 and (hook_score >= 1 or work_score >= 1) and has_external_contact:
        return True, "副業/闇バイト勧誘(コンボB検知)"

    # パターンC: 単語の密度が高い場合 (挨拶が長くても無視)
    total_scam_points = work_score + recruit_score + easy_score + hook_score
    if total_scam_points >= 4:
        # 外部誘導がなくても、怪しい単語が4つ以上重なれば「詐欺の疑い」
        return True, f"不審な勧誘文脈(密度検知: {total_scam_points}pts)"

    # 3. 個別スコアリング (予備)
    score = 0
    if has_external_contact: score += 50
    if total_scam_points >= 2: score += 30
    if re.search(r'([ａ-ｚＡ-Ｚ]．|[a-zA-Z]\.|[①-⑨]|【重要】|■注意■|▼詳細)', text): score += 20

    # 誤検知防止 (通常の挨拶のみの場合を保護)
    # ただし、コンボ判定(A, B, C)を通過している場合は救済しない
    safe_words = ["失礼します", "よろしくお願いします", "質問です"]
    if any(s in text for s in safe_words) and score < 70:
        return False, ""

    if score >= 70:
        return True, "不審な外部誘導・詐欺の疑い(スコア検知)"
    
    return False, ""

# ===============================
# Tasks
# ===============================
async def presence_rotator():
    """
    ステータスを '/help | Server Monitoring' に完全に固定する関数。
    ループや統計取得を排除した、API負荷ゼロのクリーン設計です。
    """
    await bot.wait_until_ready()

    # 二重起動防止のフラグチェック
    if getattr(bot, "_presence_running", False):
        return
    bot._presence_running = True

    try:
        # =====================================================
        # ステータス固定設定（省略・改変なし）
        # =====================================================
        await bot.change_presence(
            activity=discord.Game(name="/help | Server Monitoring")
        )
        print("Success: Presence fixed to '/help | Server Monitoring'")

    except Exception as e:
        print(f"Presence set error: {e}")
        # 失敗した場合は、フラグを下げて再試行を可能にする
        bot._presence_running = False
        return



async def ban_watcher():
    await bot.wait_until_ready()

    while not bot.is_closed():
        now = int(time.time())

        cur.execute(
            "SELECT user_id, guild_id FROM temp_bans WHERE unban_time <= ?",
            (now,)
        )
        rows = cur.fetchall()

        for user_id, guild_id in rows:
            guild = bot.get_guild(guild_id)
            if not guild:
                continue

            try:
                await guild.unban(
                    discord.Object(id=user_id),
                    reason="期限切れによる自動解除"
                )
            except:
                pass

            cur.execute(
                "DELETE FROM temp_bans WHERE user_id=? AND guild_id=?",
                (user_id, guild_id)
            )
            conn.commit()

        await asyncio.sleep(30)


# ===============================
# Audit Log
# ===============================
async def send_audit_log(
    guild: discord.Guild,
    title: str,
    fields: list,
    color: discord.Color = discord.Color.blurple()
):
    # データベースからチャンネルIDを取得
    cur.execute(
        "SELECT channel_id FROM audit_log_channel WHERE guild_id=?",
        (guild.id,)
    )
    row = cur.fetchone()
    if not row:
        return

    channel = guild.get_channel(row[0])
    if channel is None or not isinstance(channel, discord.TextChannel):
        return

    # --- Webhook取得・作成ロジック ---
    target_webhook = None
    try:
        # 既存のWebhookから "Securo Warden Logs" を探す
        webhooks = await channel.webhooks()
        for wh in webhooks:
            if wh.name == "Securo Warden Audit Logs":
                target_webhook = wh
                break
        
        # なければ作成
        if target_webhook is None:
            icon_data = None
            try:
                with open('images/securoicon.png', 'rb') as f:
                    icon_data = f.read()
            except FileNotFoundError:
                pass # 画像がない場合はアイコンなしで作成
            
            target_webhook = await channel.create_webhook(
                name="Securo Warden Audit Logs",
                avatar=icon_data,
                reason="Audit Log Webhook setup"
            )
    except Exception as e:
        print(f"Webhook error in {guild.name}: {e}")
        return # 権限不足などで作成できない場合は終了

    # --- Embed作成 (内容は変えず) ---
    embed = discord.Embed(
        title=title,
        color=color,
        timestamp=discord.utils.utcnow()
    )

    for name, value, _ in fields:
        embed.add_field(
            name=name,
            value=value if value else "なし",
            inline=False
        )

    embed.set_footer(text=f"Guild ID: {guild.id}")

    # Webhookを使って送信
    try:
        await target_webhook.send(embed=embed)
    except:
        pass




# ===============================
# Role Backup / Restore
# ===============================
async def backup_roles(guild: discord.Guild):
    cur.execute(
        "DELETE FROM role_backup WHERE guild_id=?",
        (guild.id,)
    )

    for role in guild.roles:
        if role.is_default():
            continue

        cur.execute(
            """
            INSERT INTO role_backup
            (guild_id, role_id, role_name, permissions, color, hoist, mentionable)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                guild.id,
                role.id,
                role.name,
                role.permissions.value,
                role.color.value,
                int(role.hoist),
                int(role.mentionable)
            )
        )

    conn.commit()


async def restore_roles(guild: discord.Guild):
    cur.execute(
        """
        SELECT role_id, role_name, permissions, color, hoist, mentionable
        FROM role_backup WHERE guild_id=?
        """,
        (guild.id,)
    )
    rows = cur.fetchall()

    for role_id, name, perms, color, hoist, mentionable in rows:
        role = guild.get_role(role_id)
        if not role:
            continue

        try:
            await role.edit(
                name=name,
                permissions=discord.Permissions(perms),
                color=discord.Color(color),
                hoist=bool(hoist),
                mentionable=bool(mentionable),
                reason="AntiNuke: ロール復旧"
            )
        except:
            pass


# ===============================
# AntiNuke Core Trigger
# ===============================
async def trigger_antinuke(
    guild: discord.Guild,
    reason: str
):
    # ===============================
    # 二重発動防止
    # ===============================
    cur.execute(
        "SELECT triggered FROM antinuke_state WHERE guild_id=?",
        (guild.id,)
    )
    row = cur.fetchone()
    if row and row[0] == 1:
        return

    cur.execute(
        "INSERT OR REPLACE INTO antinuke_state (guild_id, triggered) VALUES (?, 1)",
        (guild.id,)
    )
    conn.commit()

    # ===============================
    # 発動ログ（非同期）
    # ===============================
    asyncio.create_task(
        send_security_log(
            guild,
            "🚨 AntiNuke 発動",
            [
                ("理由", reason, False),
                ("サーバー", f"{guild.name} ({guild.id})", False),
            ],
            discord.Color.red()
        )
    )

    # ===============================
    # 招待リンク全削除（並列）
    # ===============================
    async def purge_invites():
        try:
            invites = await guild.invites()
            for invite in invites:
                await invite.delete(reason="AntiNuke: 招待停止")
        except:
            pass

    # ===============================
    # チャンネルロックダウン
    # ===============================
    lockdown_channels = []

    async def lockdown_channel(channel):
        overwrite = channel.overwrites_for(guild.default_role)
        backup = discord.PermissionOverwrite.from_pair(
            overwrite.pair()[0],
            overwrite.pair()[1]
        )
        lockdown_channels.append((channel, backup))

        overwrite.send_messages = False
        overwrite.connect = False

        try:
            await channel.set_permissions(
                guild.default_role,
                overwrite=overwrite,
                reason="AntiNuke: ロックダウン"
            )
        except:
            pass

    lockdown_tasks = [
        lockdown_channel(ch)
        for ch in guild.channels
        if isinstance(ch, (discord.TextChannel, discord.VoiceChannel))
    ]

    # =============================== # handle_message
    # Webhook 全削除（並列）
    # ===============================
    async def purge_webhooks(channel):
        try:
            for webhook in await channel.webhooks():
                await webhook.delete(reason="AntiNuke: Webhook削除")
        except:
            pass

    webhook_tasks = [
        purge_webhooks(ch)
        for ch in guild.text_channels
    ]

    # ===============================
    # Bot追加犯 BAN（並列）
    # ===============================
    async def ban_bot_adder():
        try:
            async for entry in guild.audit_logs(
                limit=5,
                action=discord.AuditLogAction.bot_add
            ):
                if not entry.user:
                    continue

                if isinstance(entry.user, discord.Member):
                    if is_whitelisted_member(entry.user):
                        return

                try:
                    await guild.ban(
                        entry.user,
                        reason="AntiNuke: 悪意あるBot追加"
                    )
                except:
                    pass

                asyncio.create_task(
                    send_security_log(
                        guild,
                        "🔨 AntiNuke: 招待者BAN",
                        [
                            ("対象ユーザー", f"{entry.user} ({entry.user.id})", False),
                            ("理由", "悪意あるBot追加", False),
                        ],
                        discord.Color.dark_red()
                    )
                )
                return
        except:
            pass

    # ===============================
    # ブラックリスト Bot Kick（並列）
    # ===============================
    async def kick_blacklisted_bot(member):
        try:
            await guild.kick(
                member,
                reason="AntiNuke: ブラックリストBot"
            )
            asyncio.create_task(
                send_security_log(
                    guild,
                    "🤖 Bot Kick",
                    [
                        ("対象Bot", f"{member} ({member.id})", False),
                        ("理由", "ブラックリスト登録済み", False),
                    ],
                    discord.Color.orange()
                )
            )
        except:
            pass

    kick_tasks = []
    for member in guild.members:
        if not member.bot or member.id == guild.me.id:
            continue

        cur.execute(
            "SELECT 1 FROM bot_blacklist WHERE bot_id=?",
            (member.id,)
        )
        if cur.fetchone():
            kick_tasks.append(kick_blacklisted_bot(member))

    # ===============================
    # 一斉実行
    # ===============================
    await asyncio.gather(
        purge_invites(),
        *lockdown_tasks,
        *webhook_tasks,
        ban_bot_adder(),
        *kick_tasks,
        return_exceptions=True
    )

    # ===============================
    # ロール復旧 & ロック解除（並列）
    # ===============================
    asyncio.create_task(restore_roles(guild))

    async def unlock_channel(channel, backup):
        try:
            await channel.set_permissions(
                guild.default_role,
                overwrite=backup,
                reason="AntiNuke: ロックダウン解除"
            )
        except:
            pass

    await asyncio.gather(
        *[
            unlock_channel(ch, backup)
            for ch, backup in lockdown_channels
        ],
        return_exceptions=True
    )

    # ===============================
    # トリガー解除
    # ===============================
    cur.execute(
        "UPDATE antinuke_state SET triggered=0 WHERE guild_id=?",
        (guild.id,)
    )
    conn.commit()

# 関数の外（上など）に配置して、一時的な重複を排除します
last_spam_detections = {}

async def apply_spam_timeout(
    member: discord.Member,
    guild: discord.Guild,
    reason: str
):
    """
    スパム検知時にユーザーを10分間タイムアウトさせ、セキュリティログを送信する。
    重複送信防止ロジック付き。
    """
    # --- 2重送信防止ロジック ---
    now = time_module.time()
    user_key = (guild.id, member.id)
    
    # 2秒以内に同じユーザーに対する検知があった場合は、ログ送信をスキップ
    if user_key in last_spam_detections and now - last_spam_detections[user_key] < 2:
        return
    last_spam_detections[user_key] = now
    # --------------------------

    # 1. タイムアウト処理
    try:
        # インポートに合わせて datetime.timedelta を使用
        until = discord.utils.utcnow() + datetime.timedelta(minutes=10)
        await member.timeout(until, reason=f"AntiSpam: {reason}")
        action_text = "10分間タイムアウト実行"
    except Exception as e:
        print(f"[Error] Failed to timeout {member.id}: {e}")
        action_text = f"タイムアウト失敗 ({e})"

    # 2. セキュリティログ送信
    try:
        # 第3引数に空文字 "" を入れて引数のズレを修正
        await send_security_log(
            guild,
            "🚫 AntiSpam 検知",
            "", 
            [
                ("対象ユーザー", f"{member.mention} ({member.id})", False),
                ("理由", reason, False),
                ("処理", action_text, False),
            ],
            color=discord.Color.orange()
        )
    except Exception as e:
        print(f"[Error] Failed to send security log: {e}")

async def check_admin_penalty(interaction: discord.Interaction) -> bool:
    cur.execute(
        "SELECT until FROM admin_penalties WHERE user_id=?",
        (interaction.user.id,)
    )
    row = cur.fetchone()

    if not row:
        return False

    until = row[0]
    if until is None:
        return True

    if int(time.time()) < until:
        return True

    # 期限切れ → 自動解除
    cur.execute(
        "DELETE FROM admin_penalties WHERE user_id=?",
        (interaction.user.id,)
    )
    conn.commit()

    try:
        await interaction.user.send(
            "あなたの **Securo Warden 利用停止** は自動解除されました。"
        )
    except:
        pass

    return False

# ===============================
# バックアップ作成
# ===============================
async def create_guild_backup(guild: discord.Guild) -> dict:
    data = {"roles": [], "categories": [], "channels": []}

    for role in guild.roles:
        if role.is_default():
            continue
        data["roles"].append({
            "name": role.name[:100],
            "color": role.color.value,
            "hoist": role.hoist,
            "mentionable": role.mentionable,
            "permissions": role.permissions.value,
            "position": role.position
        })

    for category in guild.categories:
        data["categories"].append({
            "name": category.name[:100],
            "position": category.position
        })

    for ch in guild.channels:
        if isinstance(ch, discord.CategoryChannel):
            continue

        data["channels"].append({
            "name": ch.name[:100],
            "type": ch.type.name,
            "category": ch.category.name[:100] if ch.category else None,
            "topic": getattr(ch, "topic", None),
            "slowmode": getattr(ch, "slowmode_delay", 0),
            "nsfw": getattr(ch, "nsfw", False)
        })

    return data

async def hash_image_from_attachment(attachment: discord.Attachment) -> str:
    data = await attachment.read()
    return hashlib.sha256(data).hexdigest()

async def safe_delete_message(message: discord.Message, reason: str = None):
    try:
        await message.channel.delete_messages(
            [message],
            reason=reason
        )
        return True
    except Exception as e:
        print("DELETE FAILED:", repr(e))
        return False

async def fetch_channel_delete_executor(
    guild: discord.Guild,
    channel_id: int
):
    """
    高速版：最大0.4秒まで
    """
    try:
        async for entry in guild.audit_logs(
            limit=3,
            action=discord.AuditLogAction.channel_delete
        ):
            if entry.target and entry.target.id == channel_id:
                return entry.user
    except:
        pass

    return None

async def send_security_webhook(title: str, fields: list, color: int = 0xff0000):
    if not WEBHOOK_URL:
        return

    embed = {
        "title": title,
        "color": color,
        "fields": [
            {
                "name": str(name)[:256],
                "value": str(value)[:1024],
                "inline": inline
            }
            for name, value, inline in fields
        ],
        "timestamp": discord.utils.utcnow().isoformat()
    }

    payload = {
        "embeds": [embed],
        "username": "Securo Warden"
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(WEBHOOK_URL, json=payload) as resp:
                if resp.status not in (200, 204):
                    text = await resp.text()
                    logging.warning(
                        f"[Webhook Error] Status: {resp.status} | Response: {text}"
                    )

    except Exception as e:
        logging.error(f"[Webhook Exception] {e}")

async def expand_url(url):
    """短縮URLを最終目的地まで展開する"""
    async with aiohttp.ClientSession() as session:
        try:
            current_url = url
            for _ in range(5): # 最大5回リダイレクトを追跡
                async with session.head(current_url, allow_redirects=True, timeout=3) as resp:
                    if str(resp.url) == current_url:
                        break
                    current_url = str(resp.url)
            return current_url
        except:
            return url

async def send_welcome_dm(user: discord.User):
    """ユーザーに導入DMを送信"""
    try:
        # 埋め込み作成
        embed = discord.Embed(
            title="BOT導入ありがとうございます！",
            description=(
                "サーバーにBOTを導入していただきありがとうございます。\n\n"
                "設定や動作で不明な点があれば、サポートサーバーで確認できます。\n"
                "サポートサーバーに参加することで使用できるコマンドも用意しています。"
            ),
            color=discord.Color.blurple()
        )

        # リンクボタン作成
        view = discord.ui.View()
        button = discord.ui.Button(
            label="サポートサーバーに参加する",
            url=SUPPORT_LINK
        )
        view.add_item(button)

        # DM送信
        await user.send(embed=embed, view=view)

    except discord.Forbidden:
        print(f"DM送信できませんでした: {user}")
    except Exception as e:
        print(f"DM送信中にエラー: {e}")

join_cache = defaultdict(list)
async def send_security_log(guild: discord.Guild, title: str, description: str, fields: list = None, color=discord.Color.red(), is_incident: bool = True):
    """
    セキュリティログをWebhook経由で送信する。
    conn, cur は外部で定義されたグローバルな接続を使用。
    is_incident: False にすると統計データ（daily_incidents）に記録しない。
    """
    # 設定の取得
    cur.execute("SELECT channel_id, webhook_url FROM security_settings WHERE guild_id=?", (guild.id,))
    row = cur.fetchone()

    if not row:
        return

    channel_id, webhook_url = row
    channel = guild.get_channel(channel_id)
    
    # チャンネルが削除されている場合は設定を削除して終了
    if not channel:
        cur.execute("DELETE FROM security_settings WHERE guild_id=?", (guild.id,))
        conn.commit()
        return

    try:
        async with aiohttp.ClientSession() as session:
            # Webhookオブジェクトの作成
            webhook = discord.Webhook.from_url(webhook_url, session=session)
            
            # Embedの構築
            embed = discord.Embed(
                title=title, 
                description=description, 
                color=color, 
                timestamp=discord.utils.utcnow()
            )
            
            if fields:
                for name, value, inline in fields:
                    # 値が空の場合のバグ回避
                    if value:
                        embed.add_field(name=name, value=value, inline=inline)
            
            embed.set_footer(text="Securo Warden Security System")
            
            # ログの送信
            await webhook.send(
                embed=embed, 
                username="Securo Warden Security Logs"
            )

            # --- 修正箇所：is_incident が True の場合のみ統計を記録 ---
            # これにより、デイリーレポート送信自体が「事件」としてカウントされるのを防ぎます。
            if is_incident:
                # 統計用にイベントを記録
                now = discord.utils.utcnow()
                cur.execute(
                    "INSERT INTO daily_incidents (guild_id, event_type, timestamp) VALUES (?, ?, ?)", 
                    (guild.id, title, now.isoformat())
                )
                conn.commit()

    except (discord.NotFound, discord.Forbidden, discord.HTTPException, ValueError) as e:
        # Webhook削除済み、URL不正、ネットワークエラーなどはログに残さずスルー
        pass

async def execute_raid_protection(guild: discord.Guild, target_members: list):
    """
    最も負荷が低く速いBAN処理と、30分間の招待一時停止を実行する
    """
    # 1. 全チャンネルのロックダウン (最速)
    # manage_roles 権限があるテキストチャンネルを対象に実行
    for channel in guild.text_channels:
        perms = channel.permissions_for(guild.me)
        if perms.manage_roles:
            overwrite = channel.overwrites_for(guild.default_role)
            if overwrite.send_messages is not False:
                overwrite.send_messages = False
                await channel.set_permissions(
                    guild.default_role, 
                    overwrite=overwrite, 
                    reason="🚨 [Anti-Raid] 緊急ロックダウン (30分間)"
                )

    # 2. セキュリティログ送信 (赤色埋め込み)
    await send_security_log(
        guild,
        "🚨 RAID攻撃を検知 - 緊急防衛プロトコル発動",
        "異常な連続参加を検知したため、招待リンクの抹消とチャンネルロックを実行しました。",
        [
            ("対象ユーザー数", f"{len(target_members)}名", True),
            ("措置内容", "一括BAN / 全隔離 / 30分間招待停止", True),
        ],
        color=discord.Color.red()
    )

    # 3. 高速並列BAN (asyncio.gather で一斉送信)
    # APIリクエストを並列化して最速で処理を回す
    tasks = [guild.ban(m, reason="🚨 [Anti-Raid] 高速一括処理: RAID加担") for m in target_members]
    await asyncio.gather(*tasks, return_exceptions=True)

    # 4. 招待リンクの削除 (バニティURL以外)
    # 監査ログに「30分間停止」を表示させるため reason を詳細に記載
    if guild.me.guild_permissions.manage_guild:
        invites = await guild.invites()
        for invite in invites:
            try:
                await invite.delete(reason="🚨 [Anti-Raid] 30分間招待停止措置 (RAID防御)")
            except:
                pass

    # 5. 30分後の解除タスクをバックグラウンドで開始
    asyncio.create_task(lift_raid_protection(guild))

async def lift_raid_protection(guild: discord.Guild):
    """
    30分待機した後にロックダウンを解除する
    """
    await asyncio.sleep(1800) # 30分 (1800秒)
    
    # ロックダウンの解除
    for channel in guild.text_channels:
        perms = channel.permissions_for(guild.me)
        if perms.manage_roles:
            overwrite = channel.overwrites_for(guild.default_role)
            # 送信禁止を中立(None)に戻す
            if overwrite.send_messages is False:
                overwrite.send_messages = None 
                await channel.set_permissions(
                    guild.default_role, 
                    overwrite=overwrite, 
                    reason="✅ [Anti-Raid] 30分経過によるロックダウン自動解除"
                )

    # 完了通知
    await send_security_log(
        guild,
        "🛡️ 防衛プロトコル終了",
        "30分が経過したため、チャンネルのロックダウンを解除しました。必要に応じて新しい招待リンクを作成してください。",
        color=discord.Color.green()
    )

async def get_or_create_securo_webhook(channel, log_type="security"):
    """
    指定されたチャンネルに既存のWebhookがあれば取得・更新し、なければ新規作成する。
    log_type: "security" または "audit" を指定
    """
    # ログタイプに応じて名前を切り替え
    if log_type == "security":
        webhook_name = "Securo Warden Security Logs"
    else:
        webhook_name = "Securo Warden Audit Logs"

    icon_path = "/home/developer/bot2/securoicon.png"
    
    # アイコンファイルの読み込み
    icon_bytes = None
    if os.path.exists(icon_path):
        try:
            with open(icon_path, "rb") as f:
                icon_bytes = f.read()
        except Exception as e:
            print(f"[WARNING] Failed to read icon file: {e}")

    try:
        # 1. チャンネル内の全Webhookを取得
        webhooks = await channel.webhooks()
        # 名前が一致するものを探す
        target_webhook = discord.utils.get(webhooks, name=webhook_name)

        if target_webhook:
            # 既存のWebhookがある場合、アイコンを最新に更新（上書き）
            if icon_bytes:
                await target_webhook.edit(avatar=icon_bytes)
            return target_webhook
        else:
            # 2. 存在しない場合は新規作成（アイコン付き）
            new_webhook = await channel.create_webhook(
                name=webhook_name,
                avatar=icon_bytes,
                reason=f"SecuroWarden {log_type}用Webhook自動作成"
            )
            print(f"[INFO] Created new webhook: {webhook_name} in {channel.id}")
            return new_webhook

    except Exception as e:
        print(f"[ERROR][Webhook] {log_type}取得失敗: {e}")
        return None

# --- 呼び出し側のイメージ ---
# security_webhook = await get_or_create_securo_webhook(target_channel, "security")
# audit_webhook = await get_or_create_securo_webhook(target_channel, "audit")

# URL展開用のキャッシュ（同じ短縮URLを何度も展開して制限にかかるのを防ぐ）
# キャッシュ管理（メモリ肥大化防止付き）
url_expand_cache = {}

async def expand_url_with_retry(url: str, max_redirects: int = 5) -> str:
    """
    短縮URLを最大5回まで追跡。
    外部ライブラリへの依存をyarl（aiohttp標準）に絞り、参照エラーを徹底排除。
    """
    if url in url_expand_cache:
        return url_expand_cache[url]

    # キャッシュが1000件を超えたら古い順に整理（簡易リセット）
    if len(url_expand_cache) > 1000:
        url_expand_cache.clear()

    current_url = url
    # タイムアウトを短く設定し、Bot全体の動作を止めない
    timeout = aiohttp.ClientTimeout(total=2.5) 
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        # クッキーを無視してセッションを軽量化
        async with aiohttp.ClientSession(timeout=timeout, headers=headers, cookie_jar=aiohttp.DummyCookieJar()) as session:
            for _ in range(max_redirects):
                async with session.head(current_url, allow_redirects=False) as response:
                    # リダイレクト系ステータス
                    if response.status in (301, 302, 303, 307, 308):
                        location = response.headers.get("Location")
                        if not location:
                            break
                        
                        # aiohttp.helpers.url_normalize の代わりに yarl.URL を直接使用 (確実)
                        # 相対パスも自動で絶対パスに変換される
                        current_url = str(response.url.join(yarl.URL(location)))
                    
                    # 200 OK や 429 レート制限などは、今のURLで確定させる
                    else:
                        break
    except Exception:
        # エラー時は「現時点でのURL」を返す（これにより、展開前のURLでブラックリスト判定が可能）
        pass

    url_expand_cache[url] = current_url
    return current_url


# Class=================================-
class AntiNukeView(discord.ui.View):
    def __init__(self, guild_id: int):
        super().__init__(timeout=None)
        self.guild_id = guild_id

    @discord.ui.button(label="🟢 有効化", style=discord.ButtonStyle.success)
    async def enable(self, interaction: discord.Interaction, button: discord.ui.Button):
        cur.execute(
            "INSERT OR REPLACE INTO antinuke_bot (guild_id, enabled) VALUES (?, 1)",
            (self.guild_id,)
        )
        conn.commit()

        await interaction.response.send_message(
            "✅ AntiNuke を **有効化** しました。",
            ephemeral=True
        )

    @discord.ui.button(label="🔴 無効化", style=discord.ButtonStyle.danger)
    async def disable(self, interaction: discord.Interaction, button: discord.ui.Button):
        cur.execute(
            "INSERT OR REPLACE INTO antinuke_bot (guild_id, enabled) VALUES (?, 0)",
            (self.guild_id,)
        )
        conn.commit()

        await interaction.response.send_message(
            "❌ AntiNuke を **無効化** しました。",
            ephemeral=True
        )

class AntiSpamView(discord.ui.View):
    def __init__(self, guild_id: int):
        super().__init__(timeout=None)  # 永続
        self.guild_id = guild_id

    @discord.ui.button(label="🟢 有効化", style=discord.ButtonStyle.success)
    async def enable(self, interaction: discord.Interaction, button: discord.ui.Button):
        cur.execute(
            "INSERT OR REPLACE INTO antispam_state (guild_id, enabled) VALUES (?, 1)",
            (self.guild_id,)
        )
        conn.commit()

        await interaction.response.send_message(
            "✅ AntiSpam を **有効化** しました。",
            ephemeral=True
        )

    @discord.ui.button(label="🔴 無効化", style=discord.ButtonStyle.danger)
    async def disable(self, interaction: discord.Interaction, button: discord.ui.Button):
        cur.execute(
            "INSERT OR REPLACE INTO antispam_state (guild_id, enabled) VALUES (?, 0)",
            (self.guild_id,)
        )
        conn.commit()

        await interaction.response.send_message(
            "❌ AntiSpam を **無効化** しました。",
            ephemeral=True
        )

class PermGuardView(discord.ui.View):
    def __init__(self, guild_id: int):
        super().__init__(timeout=None)
        self.guild_id = guild_id

    @discord.ui.button(label="有効化", style=discord.ButtonStyle.danger)
    async def enable(self, interaction: discord.Interaction, button: discord.ui.Button):
        cur.execute(
            "UPDATE perm_guard SET enabled=1 WHERE guild_id=?",
            (self.guild_id,)
        )
        conn.commit()

        await interaction.response.send_message(
            "✅ Perm Guard を有効化しました。",
            ephemeral=True
        )

    @discord.ui.button(label="無効化", style=discord.ButtonStyle.secondary)
    async def disable(self, interaction: discord.Interaction, button: discord.ui.Button):
        cur.execute(
            "UPDATE perm_guard SET enabled=0 WHERE guild_id=?",
            (self.guild_id,)
        )
        conn.commit()

        await interaction.response.send_message(
            "⛔ Perm Guard を無効化しました。",
            ephemeral=True
        )

class AlertModeView(discord.ui.View):
    def __init__(self, guild_id: int):
        super().__init__(timeout=None)
        self.guild_id = guild_id

    async def set_mode(
        self,
        interaction: discord.Interaction,
        level: str
    ):
        cur.execute(
            "INSERT OR REPLACE INTO alert_mode VALUES (?, ?)",
            (self.guild_id, level)
        )
        conn.commit()

        await interaction.response.send_message(
            f"✅ 警戒モードを **{level.upper()}** に設定しました。",
            ephemeral=True
        )

    @discord.ui.button(label="🟢 低", style=discord.ButtonStyle.success)
    async def low(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.set_mode(interaction, "low")

    @discord.ui.button(label="🟡 中", style=discord.ButtonStyle.secondary)
    async def medium(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.set_mode(interaction, "medium")

    @discord.ui.button(label="🔴 高", style=discord.ButtonStyle.danger)
    async def high(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.set_mode(interaction, "high")

# ===============================
# 通報用 Modal
# ===============================
class ReportModal(discord.ui.Modal, title="BOT利用規約違反の通報"):
    subject = discord.ui.TextInput(
        label="用件",
        placeholder="通報の要件を簡潔に入力してください",
        max_length=100,
        required=True
    )

    target_id = discord.ui.TextInput(
        label="通報対象のID",
        placeholder="ユーザーID または サーバーID",
        max_length=30,
        required=True
    )

    reason = discord.ui.TextInput(
        label="理由・詳細",
        placeholder="違反内容をできるだけ詳しく入力してください",
        style=discord.TextStyle.paragraph,
        max_length=500,
        required=True
    )

    def __init__(self, image: discord.Attachment | None):
        super().__init__()
        self.image = image

    async def on_submit(self, interaction: discord.Interaction):
        admin = interaction.client.get_user(ADMIN_USER_ID)

        if admin is None:
            await interaction.response.send_message(
                "❌ 管理者へ通知できませんでした。",
                ephemeral=True
            )
            return

        embed = discord.Embed(
            title="🚨 BOT 利用規約違反 通報",
            color=discord.Color.red(),
            timestamp=discord.utils.utcnow()
        )

        embed.add_field(
            name="👤 通報者",
            value=f"{interaction.user} ({interaction.user.id})",
            inline=False
        )
        embed.add_field(
            name="📌 用件",
            value=self.subject.value,
            inline=False
        )
        embed.add_field(
            name="🎯 通報対象ID",
            value=self.target_id.value,
            inline=False
        )
        embed.add_field(
            name="📝 理由",
            value=self.reason.value,
            inline=False
        )

        if interaction.guild:
            embed.set_footer(text=f"Guild ID: {interaction.guild.id}")
        else:
            embed.set_footer(text="DMからの通報")

        # ===============================
        # 画像添付（任意）
        # ===============================
        if self.image:
            embed.set_image(url=self.image.url)

        try:
            await admin.send(embed=embed)
        except discord.Forbidden:
            await interaction.response.send_message(
                "❌ 管理者のDMが閉じられています。",
                ephemeral=True
            )
            return

        await interaction.response.send_message(
            "✅ 通報を送信しました。ご協力ありがとうございます。",
            ephemeral=True
        )

# ===============================
# 通報理由入力フォーム
# ===============================
class ReportReasonModal(discord.ui.Modal, title="Report Message"):

    reason = discord.ui.TextInput(
        label="Reason",
        style=discord.TextStyle.paragraph,
        max_length=1000,
        required=True
    )

    def __init__(self, message: discord.Message):
        super().__init__()
        self.message = message

    async def on_submit(self, interaction: discord.Interaction):

        # 通報ログチャンネル取得
        cur.execute(
            "SELECT channel_id FROM report_log_channel WHERE guild_id=?",
            (interaction.guild.id,)
        )
        row = cur.fetchone()

        if not row:
            await interaction.response.send_message(
                "❌ 通報ログチャンネルが設定されていません。",
                ephemeral=True
            )
            return

        log_channel = interaction.guild.get_channel(row[0])
        if not log_channel:
            await interaction.response.send_message(
                "❌ 設定された通報ログチャンネルが見つかりません。",
                ephemeral=True
            )
            return

        reported_message = self.message

        # Embed作成
        embed = discord.Embed(
            title="🚨 Message Reported",
            color=discord.Color.orange()
        )

        embed.add_field(
            name="📨 Reported by",
            value=f"{interaction.user} ({interaction.user.id})",
            inline=False
        )
        embed.add_field(
            name="👤 Target User",
            value=f"{reported_message.author} ({reported_message.author.id})",
            inline=False
        )
        embed.add_field(
            name="📝 Message Content",
            value=reported_message.content[:1024] if reported_message.content else "*No text*",
            inline=False
        )
        embed.add_field(
            name="📌 Reason",
            value=self.reason.value,
            inline=False
        )

        embed.timestamp = discord.utils.utcnow()

        view = ReportLogView(reported_message)

        await log_channel.send(embed=embed, view=view)

        await interaction.response.send_message(
            "✅ 通報を送信しました。ご協力ありがとうございます。",
            ephemeral=True
        )

# ===============================
# 通報ログ操作View
# ===============================
class ReportLogView(discord.ui.View):
    def __init__(self, message: discord.Message):
        super().__init__(timeout=None)
        self.message = message

    @discord.ui.button(label="Delete Message", style=discord.ButtonStyle.danger)
    async def delete_message(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button
    ):
        if not interaction.user.guild_permissions.manage_messages:
            await interaction.response.send_message(
                "❌ メッセージ管理権限がありません。",
                ephemeral=True
            )
            return

        try:
            await self.message.delete()
            await interaction.response.send_message(
                "✅ メッセージを削除しました。",
                ephemeral=True
            )
        except:
            await interaction.response.send_message(
                "❌ メッセージの削除に失敗しました。",
                ephemeral=True
            )

class InviteSafeModeView(discord.ui.View):
    def __init__(self, guild_id: int):
        super().__init__(timeout=None)
        self.guild_id = guild_id

    @discord.ui.button(label="🟢 有効化", style=discord.ButtonStyle.success)
    async def enable(self, interaction: discord.Interaction, button: discord.ui.Button):
        cur.execute(
            "INSERT OR REPLACE INTO invite_safemode (guild_id, enabled) VALUES (?, 1)",
            (self.guild_id,)
        )
        conn.commit()

        await interaction.response.send_message(
            "✅ Invite SafeMode を **有効化** しました。",
            ephemeral=True
        )

    @discord.ui.button(label="🔴 無効化", style=discord.ButtonStyle.danger)
    async def disable(self, interaction: discord.Interaction, button: discord.ui.Button):
        cur.execute(
            "INSERT OR REPLACE INTO invite_safemode (guild_id, enabled) VALUES (?, 0)",
            (self.guild_id,)
        )
        conn.commit()

        await interaction.response.send_message(
            "❌ Invite SafeMode を **無効化** しました。",
            ephemeral=True
        )

class PurgeConfirmView(discord.ui.View):
    def __init__(self, author_id: int):
        super().__init__(timeout=None)  # ボタンは永久
        self.author_id = author_id
        self.confirmed = False

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        return interaction.user.id == self.author_id

    @discord.ui.button(label="実行する", style=discord.ButtonStyle.danger)
    async def confirm(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button
    ):
        self.confirmed = True
        self.stop()
        await interaction.response.defer()

    @discord.ui.button(label="キャンセル", style=discord.ButtonStyle.secondary)
    async def cancel(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button
    ):
        self.confirmed = False
        self.stop()
        await interaction.response.defer()

class BackupConfirmView(discord.ui.View):
    def __init__(self, user_id, key):
        super().__init__(timeout=60)
        self.user_id = user_id
        self.key = key

    async def interaction_check(self, interaction):
        return interaction.user.id == self.user_id

    # ===== 実行 =====
    @discord.ui.button(label="実行", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button):

        guild = interaction.guild

        cur.execute(
            "SELECT owner_user_id, source_guild_id, data FROM backups WHERE backup_key=?",
            (self.key,)
        )
        row = cur.fetchone()

        if not row:
            await interaction.response.send_message("❌ 無効なキーです。", ephemeral=True)
            return

        owner_user_id, source_guild_id, data_json = row

        if interaction.user.id != owner_user_id or interaction.user.id != guild.owner_id:
            await interaction.response.send_message("❌ 実行権限がありません。", ephemeral=True)
            return

        if guild.id == source_guild_id:
            await interaction.response.send_message("❌ 同じサーバーには復元できません。", ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)

        try:
            data = json.loads(data_json)
        except:
            await interaction.followup.send("❌ バックアップデータ破損。", ephemeral=True)
            return

        # ===== チャンネル削除 =====
        for ch in guild.channels:
            try:
                await ch.delete()
            except:
                continue

        # ===== ロール削除 =====
        for role in guild.roles:
            if role.is_default() or role >= guild.me.top_role:
                continue
            try:
                await role.delete()
            except:
                continue

        # ===== ロール作成 =====
        role_map = {}
        for r in sorted(data["roles"], key=lambda x: x["position"]):
            try:
                role = await guild.create_role(
                    name=r["name"],
                    permissions=discord.Permissions(r["permissions"]),
                    color=discord.Color(r["color"]),
                    hoist=r["hoist"],
                    mentionable=r["mentionable"]
                )
                role_map[r["name"]] = role
            except:
                continue

        # ===== カテゴリ =====
        category_map = {}
        for c in data["categories"]:
            try:
                cat = await guild.create_category(
                    name=c["name"],
                    position=c["position"]
                )
                category_map[c["name"]] = cat
            except:
                continue

        # ===== チャンネル =====
        for ch in data["channels"]:
            try:
                category = category_map.get(ch["category"])
                if ch["type"] == "text":
                    await guild.create_text_channel(
                        name=ch["name"],
                        category=category,
                        topic=ch["topic"],
                        slowmode_delay=ch["slowmode"],
                        nsfw=ch["nsfw"]
                    )
                elif ch["type"] == "voice":
                    await guild.create_voice_channel(
                        name=ch["name"],
                        category=category
                    )
            except:
                continue

        await interaction.followup.send("✅ 復元が完了しました。", ephemeral=True)

    # ===== キャンセル =====
    @discord.ui.button(label="キャンセル", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button):
        await interaction.response.send_message(
            "キャンセルしました。",
            ephemeral=True
        )

class TermsView(discord.ui.View):

    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(
        label="利用規約に同意する",
        style=discord.ButtonStyle.green,
        custom_id="agree_terms_button"
    )
    async def agree(self, interaction: discord.Interaction, button: discord.ui.Button):

        try:

            cur.execute("SELECT version FROM terms_current LIMIT 1")
            current_version = cur.fetchone()[0]

            cur.execute(
                "INSERT OR REPLACE INTO terms_agreed (user_id, version) VALUES (?, ?)",
                (interaction.user.id, current_version)
            )

            conn.commit()

            await interaction.response.send_message(
                "✅ 利用規約に同意しました。引き続きサービスを利用できます。",
                ephemeral=True
            )

        except Exception:

            try:
                await interaction.response.send_message(
                    "❌ エラーが発生しました。",
                    ephemeral=True
                )
            except:
                pass

# 1. 計算認証用モーダル (uuID & 回答速度チェック)
class CalculationModal(discord.ui.Modal):
    def __init__(self, a, b, role):
        # 内部IDをUUIDにして、ツールがIDを固定できないようにする
        super().__init__(title="計算認証", custom_id=f"calc_{uuid.uuid4()}")
        self.answer = str(a + b)
        self.role = role
        self.start_time = time.time()
        
        self.input_text = discord.ui.TextInput(
            label=f"{a} + {b} の答えを入力してください",
            placeholder="半角数字で回答...",
            min_length=1, max_length=2, required=True
        )
        self.add_item(self.input_text)

    async def on_submit(self, interaction: discord.Interaction):
        # 人間味チェック：あまりに速すぎる回答（例：0.5秒未満）はツールと判定
        if time.time() - self.start_time < 0.5:
            return await interaction.response.send_message(ERROR_BOT_DETECTED, ephemeral=True)

        if self.input_text.value == self.answer:
            await interaction.user.add_roles(self.role)
            await interaction.response.send_message(f"✅認証完了！ {self.role.mention}を付与しました。", ephemeral=True)
        else:
            await interaction.response.send_message("❌答えが違います。もう一度やり直してください。", ephemeral=True)

# 2. ランダムコード認証用モーダル (動的ID & 回答速度チェック)
class RandomCodeModal(discord.ui.Modal):
    def __init__(self, code, role):
        super().__init__(title="ランダムコード認証", custom_id=f"code_{uuid.uuid4()}")
        self.code = code
        self.role = role
        self.start_time = time.time()
        
        self.input_text = discord.ui.TextInput(
            label=f"表示されたコード「{code}」を入力してください",
            placeholder="コードを入力...",
            min_length=7, max_length=7, required=True
        )
        self.add_item(self.input_text)

    async def on_submit(self, interaction: discord.Interaction):
        # コードの読み取り時間を考慮し、0.8秒未満をツールと判定
        if time.time() - self.start_time < 0.8:
            return await interaction.response.send_message(ERROR_BOT_DETECTED, ephemeral=True)

        if self.input_text.value == self.code:
            await interaction.user.add_roles(self.role)
            await interaction.response.send_message(f"✅認証完了！ {self.role.mention}を付与しました。", ephemeral=True)
        else:
            await interaction.response.send_message("❌コードが一致しませんでした。", ephemeral=True)

# 3. サーバー名選択用セレクトメニュー (ハニーポット & UUIDバリュー)
class ServerNameModal(discord.ui.View):
    def __init__(self, role):
        super().__init__(timeout=None)
        self.role = role
        self.correct_name = role.guild.name
        self.correct_value = str(uuid.uuid4()) # 正解の値をランダム化

        # サーバー名のリスト作成
        suffixes = ["!", "!!", "?", ".", " server", " #1", " (official)", " _", " -", " 2026"]
        options_list = [self.correct_name]
        for s in suffixes:
            options_list.append(f"{self.correct_name}{s}")
        
        random.shuffle(options_list)
        final_options = options_list[:10]

        # セレクトメニュー本体 (custom_idをUUID化)
        select = discord.ui.Select(
            custom_id=f"select_{uuid.uuid4()}",
            placeholder="正しいサーバー名を選択してください",
            options=[
                discord.SelectOption(
                    label=name, 
                    value=self.correct_value if name == self.correct_name else str(uuid.uuid4())
                ) for name in final_options
            ]
        )
        select.callback = self.select_callback
        self.add_item(select)

        # 罠ボタン（ハニーポット）：ツールが叩きそうなIDを罠として設置
        trap = discord.ui.Button(label="確定", style=discord.ButtonStyle.gray, custom_id="verify_confirm")
        async def trap_callback(interaction: discord.Interaction):
            await interaction.response.send_message(ERROR_BOT_DETECTED, ephemeral=True)
        trap.callback = trap_callback
        self.add_item(trap)

    async def send_initial_response(self, interaction: discord.Interaction):
        await interaction.response.send_message(content="サーバー名を正しく選択してください", view=self, ephemeral=True)

    async def select_callback(self, interaction: discord.Interaction):
        selected_value = interaction.data['values'][0]
        if selected_value == self.correct_value:
            await interaction.user.add_roles(self.role)
            await interaction.response.send_message(f"✅認証完了！ {self.role.mention}を付与しました。", ephemeral=True)
        else:
            await interaction.response.send_message("❌正しく選択されませんでした。", ephemeral=True)
        self.stop()

# 4. 認証パネルのボタンView (アカウント作成日チェック & 罠)
class PersistentView(discord.ui.View):
    def __init__(self, auth_type: str, role_id: int):
        super().__init__(timeout=None)
        self.auth_type = auth_type
        self.role_id = role_id
        
        # 【修正ポイント】
        # 永続Viewは custom_id が一致することで再起動後も動作します。
        # role_id を含めることで、サーバーごとに異なるロール設定を正しく識別させます。
        self.verify.custom_id = f"verify_button_{role_id}"

    @discord.ui.button(label="✅認証", style=discord.ButtonStyle.green)
    async def verify(self, interaction: discord.Interaction, button: discord.ui.Button):
        # 1. サーバー（Guild）の取得
        guild = interaction.guild
        
        # 2. ロールの取得 (キャッシュで見つからない場合はAPIから直接取得)
        role = guild.get_role(self.role_id)
        if not role:
            try:
                role = await guild.fetch_role(self.role_id)
            except discord.NotFound:
                return await interaction.response.send_message("❌設定されたロールが見つかりません。", ephemeral=True)
            except Exception:
                return await interaction.response.send_message("❌ロールの取得中にエラーが発生しました。", ephemeral=True)

        # 3. 【追加】既に認証済み（ロールを所有）かチェック
        if role in interaction.user.roles:
            return await interaction.response.send_message("⚠️あなたは既に認証されているようです。", ephemeral=True)

        # 4. 防壁：アカウント作成から24時間以内はツール率が高いため弾く
        if (discord.utils.utcnow() - interaction.user.created_at).days < 1:
            return await interaction.response.send_message("❌セキュリティ保護のため、作成から24時間未満のアカウントは認証できません。", ephemeral=True)

        # 5. Botの権限チェック
        if not guild.me.guild_permissions.manage_roles:
            return await interaction.response.send_message("❌Botの権限「ロール管理」が不足しています。", ephemeral=True)
        if guild.me.top_role <= role:
            return await interaction.response.send_message("❌Botのロール順位が付与ロールより低いため操作できません。", ephemeral=True)

        # 6. 各認証方式の実行
        try:
            if self.auth_type == "ワンクリック認証":
                await interaction.user.add_roles(role)
                await interaction.response.send_message(f"✅認証完了！ {role.mention}を付与しました。", ephemeral=True)

            elif self.auth_type == "計算":
                a, b = random.randint(1, 9), random.randint(1, 9)
                await interaction.response.send_modal(CalculationModal(a, b, role))

            elif self.auth_type == "サーバー名選択":
                view = ServerNameModal(role)
                await view.send_initial_response(interaction)

            elif self.auth_type == "ランダムコード":
                random_code = ''.join(random.choices(string.ascii_letters + string.digits, k=7))
                await interaction.response.send_modal(RandomCodeModal(random_code, role))
        
        except Exception as e:
            await interaction.response.send_message(f"❌エラーが発生しました。時間を置いてやり直してください。", ephemeral=True)

class ConfirmView(discord.ui.View):
    def __init__(self, title, message, author_id):
        # timeout=None により、長時間放置してもボタンが反応し続けます
        super().__init__(timeout=None)
        self.title = title
        self.message = message
        self.author_id = author_id

    @discord.ui.button(label="実行", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        # 実行権限者（コマンドを打った本人）かチェック
        if interaction.user.id != self.author_id:
            return await interaction.response.send_message("❌ 実行者本人のみ操作可能です。", ephemeral=True)

        # 最初の応答：処理開始を通知（ephemeral=True）
        await interaction.response.send_message("🚀 オーナーにDMを送信中です。しばらくお待ちください...", ephemeral=True)
        
        # ボタンを無効化して多重クリックを防止
        for item in self.children:
            item.disabled = True
        await interaction.edit_original_response(view=self)

        # 埋め込みメッセージの作成（赤色：極めて重大な通知）
        embed = discord.Embed(title=self.title, description=self.message, color=0xFF0000)
        embed.set_footer(text="※このメッセージはシステムより全サーバーオーナーへ一斉送信されています。")

        # 重複送信防止用のセット
        sent_owners = set()
        all_guilds = interaction.client.guilds
        total_guilds = len(all_guilds)
        
        # 全サーバーをループしてオーナーに送信
        for i, guild in enumerate(all_guilds):
            # オーナー情報を取得
            owner = guild.owner
            
            if owner:
                # すでに送信済みのオーナーならスキップ
                if owner.id in sent_owners:
                    print(f"[{i+1}/{total_guilds}] スキップ (既送信オーナー): {guild.name} (Owner: {owner})")
                    continue

                try:
                    # DM送信
                    await owner.send(embed=embed)
                    sent_owners.add(owner.id) # 送信済みリストに追加
                    print(f"[{i+1}/{total_guilds}] 送信成功: {guild.name} (Owner: {owner})")
                except Exception as e:
                    # DM拒否やブロック等のエラーはスキップして次へ
                    print(f"[{i+1}/{total_guilds}] 送信失敗: {guild.name} - 理由: {e}")
            
            # スパム判定回避のため、最後のループ以外は20秒待機
            # (スキップした場合でも待機を入れることで、より安全にレート制限を回避します)
            if i < total_guilds - 1:
                await asyncio.sleep(20)

        # 完了通知（followupを使用し、これも ephemeral=True）
        await interaction.followup.send("✅ 全サーバーオーナーへの送信が完了しました（重複は自動的にスキップされました）。", ephemeral=True)
        self.stop()

    @discord.ui.button(label="キャンセル", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.author_id:
            return await interaction.response.send_message("❌ 実行者本人のみ操作可能です。", ephemeral=True)
            
        await interaction.response.send_message("✅ 送信がキャンセルされました。", ephemeral=True)
        self.stop()
        # 確認用のメッセージ（元のインタラクション）を削除
        await interaction.delete_original_response()

class AntiPhishingView(discord.ui.View):
    def __init__(self, guild_id):
        super().__init__(timeout=None)
        self.guild_id = guild_id

    @discord.ui.button(label="有効化", style=discord.ButtonStyle.red, custom_id="ap_enable")
    async def enable(self, interaction: discord.Interaction, button: discord.ui.Button):
        cur.execute("INSERT OR REPLACE INTO antiphishing_state VALUES (?, 1)", (self.guild_id,))
        conn.commit()
        await interaction.response.send_message("🛡️ Anti-Phishing 機能を**有効**にしました。", ephemeral=True)

    @discord.ui.button(label="無効化", style=discord.ButtonStyle.gray, custom_id="ap_disable")
    async def disable(self, interaction: discord.Interaction, button: discord.ui.Button):
        cur.execute("INSERT OR REPLACE INTO antiphishing_state VALUES (?, 0)", (self.guild_id,))
        conn.commit()
        await interaction.response.send_message("⚪ Anti-Phishing 機能を**無効**にしました。", ephemeral=True)

class EmbedCreateModal(discord.ui.Modal, title="Embed メッセージ作成"):
    # 1. タイトル入力（最大20文字）
    embed_title = discord.ui.TextInput(
        label="埋め込みのタイトルを20文字以内で入力してください",
        placeholder="例: サーバールール",
        min_length=1,
        max_length=20,
        required=True
    )
    
    # 2. 内容入力（最大300文字）
    embed_content = discord.ui.TextInput(
        label="内容を300文字以内で入力してください",
        style=discord.TextStyle.paragraph,
        placeholder="ここにルールや案内を入力...",
        min_length=1,
        max_length=300,
        required=True
    )

    async def on_submit(self, interaction: discord.Interaction):
        # Embedの作成
        embed = discord.Embed(
            title=self.embed_title.value,
            description=self.embed_content.value,
            color=DEFAULT_COLOR,
            timestamp=datetime.datetime.now()
        )
        embed.set_footer(text=f"作成者: {interaction.user.display_name}")

        # コマンドを実行したチャンネルに送信
        await interaction.channel.send(embed=embed)
        
        # 実行者への完了通知（本人のみ見える）
        await interaction.response.send_message("✅ Embedを送信しました！", ephemeral=True)

    async def on_error(self, interaction: discord.Interaction, error: Exception):
        # エラー発生時の安全なフィードバック
        if not interaction.response.is_done():
            await interaction.response.send_message(
                f"❌ エラーが発生しました。入力内容を確認してください。\n`{error}`", 
                ephemeral=True
            )

class AntiRaidView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="有効化", style=discord.ButtonStyle.danger, custom_id="antiraid_enable")
    async def enable(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not interaction.user.guild_permissions.manage_guild:
            return await interaction.response.send_message("❌ 権限がありません。", ephemeral=True)
        
        cur.execute("INSERT OR REPLACE INTO antiraid_settings (guild_id, enabled) VALUES (?, 1)", (interaction.guild.id,))
        conn.commit()
        await interaction.response.send_message("✅ Anti-Raid機能を**有効**にしました。異常な連続参加を検知すると自動で招待を停止します。", ephemeral=True)

    @discord.ui.button(label="無効化", style=discord.ButtonStyle.secondary, custom_id="antiraid_disable")
    async def disable(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not interaction.user.guild_permissions.manage_guild:
            return await interaction.response.send_message("❌ 権限がありません。", ephemeral=True)
            
        cur.execute("INSERT OR REPLACE INTO antiraid_settings (guild_id, enabled) VALUES (?, 0)", (interaction.guild.id,))
        conn.commit()
        await interaction.response.send_message("✅ Anti-Raid機能を**無効**にしました。", ephemeral=True)

# ===============================
# 起動イベント
# ===============================
@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} ({bot.user.id})")

    # --- A. 統計レポート・バックグラウンドタスク起動 ---
    try:
        if not daily_stats_report.is_running():
            daily_stats_report.start()
            print("Daily stats report task started")
    except Exception as e:
        print(f"Daily report start error: {e}")

    if not hasattr(bot, "presence_task") or bot.presence_task.done():
        bot.presence_task = asyncio.create_task(presence_rotator())
        print("Presence rotator started")

    if not hasattr(bot, "ban_task") or bot.ban_task.done():
        bot.ban_task = asyncio.create_task(ban_watcher())
        print("Ban watcher started")

    # --- B. ギルド単位のView登録 (AntiNuke等) ---
    # setup_hook時点ではbot.guildsが空の場合があるため、ここで行う
    try:
        for guild in bot.guilds:
            bot.add_view(AntiNukeView(guild.id))
            bot.add_view(AntiSpamView(guild.id))
            bot.add_view(PermGuardView(guild.id))
            bot.add_view(AlertModeView(guild.id))
            bot.add_view(InviteSafeModeView(guild.id))
    except Exception as e:
        print("Guild View registration error:", e)

    # --- C. 重いWebhook同期をバックグラウンドで実行 (awaitしない) ---
    asyncio.create_task(sync_webhook_icons())

async def sync_webhook_icons():
    """Webhookアイコンの更新。重い処理なのでバックグラウンドで実行"""
    try:
        print("Starting global webhook icon sync...")
        icon_path = "/home/developer/bot2/securoicon.png"
        target_names = ["Securo Warden Security Logs", "Securo Warden Audit Logs"]
        
        if os.path.exists(icon_path):
            with open(icon_path, "rb") as f:
                icon_bytes = f.read()

            for guild in bot.guilds:
                for channel in guild.text_channels:
                    try:
                        # Webhook一覧の取得（ここでもリクエストが発生するため少し待機を推奨）
                        webhooks = await channel.webhooks()
                        await asyncio.sleep(0.5) 
                        
                        for wh in webhooks:
                            if wh.name in target_names:
                                # アイコンの更新実行
                                await wh.edit(avatar=icon_bytes)
                                print(f"[SUCCESS] Updated icon: {wh.name} in {guild.name}")
                                
                                # レートリミット回避のための待機（1〜2秒が安全圏）
                                await asyncio.sleep(2.0)
                                
                    except discord.Forbidden:
                        continue
                    except discord.HTTPException as e:
                        # レートリミット(429)が発生した場合は長めに待機
                        if e.status == 429:
                            retry_after = e.retry_after if hasattr(e, 'retry_after') else 60
                            print(f"[RATE LIMIT] Waiting for {retry_after}s...")
                            await asyncio.sleep(retry_after)
                        continue
                    except Exception as e:
                        continue
                        
        print("Webhook icon sync completed successfully")
    except Exception as e:
        print(f"Webhook sync error: {e}")

async def setup_hook():
    # --- A. App Commands Sync (一度だけ実行) ---
    if not hasattr(bot, "commands_synced") or not bot.commands_synced:
        try:
            # 1. グローバル同期
            synced_global = await bot.tree.sync()
            print(f"App commands synced globally ({len(synced_global)})")

            # 2. 運営専用サーバーへの即時同期
            admin_guild = discord.Object(id=int(MODERATION_SERVER_ID))
            bot.tree.copy_global_to(guild=admin_guild)
            synced_admin = await bot.tree.sync(guild=admin_guild)
            print(f"Admin commands synced to moderation server ({len(synced_admin)})")
            
            bot.commands_synced = True
        except Exception as e:
            print("Sync error:", e)

    # --- B. 永続View登録 (DBおよび固定View) ---
    if not hasattr(bot, "persistent_views_loaded") or not bot.persistent_views_loaded:
        try:
            # 固定Viewの登録
            bot.add_view(TermsView())

            # DBから認証パネルの設定を読み込んで登録
            # role_idに基づいてcustom_idが生成されるPersistentViewを、
            # DBに保存されている全てのサーバー設定分、ループで登録します。
            cur.execute("SELECT auth_type, role_id FROM auth_settings")
            auth_rows = cur.fetchall()
            
            for row in auth_rows:
                a_type, r_id = row
                # PersistentView内部で self.verify.custom_id = f"verify_button_{role_id}" と
                # 設定されているため、ここで登録することで再起動後もインタラクションを維持できます。
                bot.add_view(PersistentView(auth_type=str(a_type), role_id=int(r_id)))
            
            print(f"Auth views synced: {len(auth_rows)} panels loaded from DB")
            bot.persistent_views_loaded = True
        except Exception as e:
            print("Setup View error:", e)

# 実行
bot.setup_hook = setup_hook

# ===============================
# メッセージ削除ログ
# ===============================
@bot.event
async def on_message_delete(message: discord.Message):
    if not message.guild:
        return

    deleter = None

    # メッセージの送信者が取得できるか確認（キャッシュ切れ対策）
    author_available = message.author is not None

    # ======================
    # 🔎 監査ログから削除者取得
    # ======================
    if message.guild.me.guild_permissions.view_audit_log:
        try:
            async for entry in message.guild.audit_logs(
                limit=5,
                action=discord.AuditLogAction.message_delete
            ):
                # 送信者情報が確定している場合は、そのターゲットIDと照合
                if author_available and entry.target and entry.target.id == message.author.id:
                    # 時間が近いログのみ採用（Discord APIの遅延を考慮し5秒以内）
                    if (discord.utils.utcnow() - entry.created_at).total_seconds() < 5:
                        # Botによる削除は無視
                        if entry.user.bot:
                            return

                        deleter = entry.user
                        break
                
                # 【追加】キャッシュ切れで送信者が不明な場合、直近5秒以内の削除ログがあればそれを採用
                elif not author_available:
                    if (discord.utils.utcnow() - entry.created_at).total_seconds() < 5:
                        if entry.user.bot:
                            return
                        deleter = entry.user
                        break
        except Exception as e:
            print(f"[LOG ERROR][on_message_delete] Audit log fetch failed: {repr(e)}")

    # ======================
    # 🔹 自己削除（監査ログに残らない）
    # ======================
    if deleter is None:
        if author_available:
            # Bot自身のメッセージ削除は記録しない
            if message.author.bot:
                return
            deleter = message.author
        else:
            # 送信者も削除者も特定できない場合のフォールバックテキスト用
            deleter = None

    # ======================
    # 🧾 表示用テキスト
    # ======================
    if author_available:
        sender_text = f"{message.author} ({message.author.id})"
    else:
        sender_text = "不明なユーザー (古いメッセージ)"

    if deleter:
        deleter_text = f"{deleter} ({deleter.id})"
    else:
        # 監査ログになく、自己削除とも断定できない場合
        if not author_available:
            deleter_text = "本人 または 権限持ちのユーザー"
        else:
            deleter_text = f"{message.author} ({message.author.id}) [自己削除]"

    # メッセージ内容の安全な取得
    content = message.content if (hasattr(message, 'content') and message.content) else "（なし、または取得不可）"

    # 送信時刻の安全な取得
    if message.created_at:
        time_text = message.created_at.strftime("%Y/%m/%d %H:%M")
    else:
        time_text = "不明"

    # ======================
    # 📤 ログ送信
    # ======================
    try:
        await send_audit_log(
            message.guild,
            "🗑️ メッセージ削除",
            [
                ("チャンネル", message.channel.mention if message.channel else f"#{message.channel_id}", True),
                ("送信者", sender_text, False),
                ("削除者", deleter_text, False),
                ("内容", content, False),
                ("送信時刻", time_text, True)
            ],
            discord.Color.dark_gray()
        )
    except Exception as e:
        print(f"[LOG ERROR][on_message_delete] Failed to send log: {repr(e)}")


# ===============================
# メッセージ編集ログ
# ===============================
@bot.event
async def on_message_edit(before, after):
    if not before.guild or before.author.bot:
        return

    if before.content == after.content:
        return

    await send_audit_log(
        before.guild,
        "✏️ メッセージ編集",
        [
            ("チャンネル", before.channel.mention, True),
            ("送信者", before.author.mention, True),
            ("変更前", before.content, False),
            ("変更後", after.content, False)
        ],
        discord.Color.blue()
    )

# 2重実行防止用のキャッシュ（ファイルの先頭の方、または関数の外に配置）
last_action_cache = {}

@bot.event
async def on_message(message: discord.Message):
    if not message.guild or message.author.bot:
        return

    guild = message.guild
    member = message.author
    now_ts = time_module.time()

    # ==================================================
    # Alert Mode / 設定情報の取得
    # ==================================================
    cur.execute("SELECT level FROM alert_mode WHERE guild_id=?", (guild.id,))
    alert_row = cur.fetchone()
    alert_level = alert_row[0] if alert_row else "low"

    cur.execute("SELECT enabled FROM antiphishing_state WHERE guild_id=?", (guild.id,))
    ap_row = cur.fetchone()
    ap_enabled = ap_row[0] == 1 if ap_row else False

    cur.execute("SELECT enabled FROM antispam_state WHERE guild_id=?", (guild.id,))
    as_row = cur.fetchone()
    as_enabled = as_row[0] == 1 if as_row else False

    # ==================================================
    # ホワイトリスト判定（Alert Mode: High の場合は無視される）
    # ==================================================
    is_whitelisted = False
    if isinstance(member, discord.Member):
        if is_whitelisted_member(member):
            if alert_level != "high":
                is_whitelisted = True

    # ==================================================
    # 画像ブラックリスト検知（即アウト・独立）
    # ==================================================
    if message.attachments and not is_whitelisted:
        for attachment in message.attachments:
            if attachment.content_type and attachment.content_type.startswith("image/"):
                try:
                    image_hash = await hash_image_from_attachment(attachment)
                except:
                    continue

                cur.execute("SELECT 1 FROM image_blacklist WHERE image_hash=?", (image_hash,))
                if cur.fetchone():
                    await safe_delete_message(message, reason="ブラックリスト画像検知")
                    await send_security_log(
                        guild,
                        "🚫 ブラックリスト画像削除",
                        "",
                        [
                            ("ユーザー", f"{member} ({member.id})", False),
                            ("チャンネル", message.channel.mention, False),
                        ],
                        discord.Color.red()
                    )
                    return

    # ホワイトリストならここでコマンド処理へ移行
    if is_whitelisted:
        await bot.process_commands(message)
        return

    # ==================================================
    # 共通変数準備
    # ==================================================
    now = int(now_ts)
    content_raw = message.content.lower()
    content_normalized = unicodedata.normalize('NFKC', message.content).lower()

    # ==================================================
    # Anti-Phishing & Scam 検知エンジン (完全版)
    # ==================================================
    if ap_enabled:
        is_detected = False
        is_hard_blacklisted = False
        reason = ""

        # 1. 詐欺・副業勧誘の文脈検知 (CW詐欺対策)
        scam_detected, scam_reason = is_advanced_scam_detection(content_normalized)
        if scam_detected:
            is_detected, reason = True, scam_reason

        # 2. URL解析 (リダイレクト・ドメイン解析)
        if not is_detected:
            urls = re.findall(r'https?://[\w/:%#\$&\?\(\)~\.=\+\-]+', message.content)
            
            for url in urls:
                clean_url = url.rstrip('.,)〉」』')
                final_url = await expand_url_with_retry(clean_url, max_redirects=5)
                
                domain_match = re.search(r'https?://([^/:\s?#]+)', final_url.lower())
                if not domain_match: continue
                domain = domain_match.group(1)

                # 既知の「展開不要な悪質URLパターン」
                if "is.gd/wpgsma" in final_url.lower() or "spoo.me/" in final_url.lower():
                    if any(bad in final_url.lower() for bad in ["wpgsma", "distopia"]):
                        is_detected, is_hard_blacklisted, reason = True, True, "既知のフィッシング短縮リンク検知"
                        break

                # タイポスクワッティング
                for official in OFFICIAL_DOMAINS:
                    dist = levenshtein_distance(domain, official)
                    if 0 < dist <= 2:
                        is_detected, reason = True, f"タイポスクワッティング検知 ({official} に酷似)"
                        break
                if is_detected: break

                # 制限ドメイン (晒し/詐欺サイト関連)
                bad_keywords = ["rt-bot.com", "doogle.gg", "doublecounter.gg", "discird.com", "discrod-"]
                if any(k in domain for k in bad_keywords):
                    is_detected, is_hard_blacklisted, reason = True, True, f"制限対象ドメイン検知 ({domain})"
                    break

                if any(b in final_url.lower() for b in HARD_BLACKLIST):
                    is_detected, reason = True, f"ブラックリストURL検知 ({domain})"
                    break

                # 形式異常判定 (ランダムドメイン対策)
                if re.search(r'www(?![\.])', domain) or (len(domain.split('.')[0]) > 15 and re.search(r'[^aeiou]{7,}', domain)):
                    is_detected, reason = True, "不正なURL形式/ランダムドメイン検知"
                    break

        # 検知確定後のアクション (削除・タイムアウト・ログ)
        if is_detected:
            cache_key = (guild.id, member.id, "phish")
            if cache_key in last_action_cache and now_ts - last_action_cache[cache_key] < 3:
                return

            last_action_cache[cache_key] = now_ts
            await safe_delete_message(message, reason)
            
            action_text = "メッセージ削除"
            try:
                # 詐欺・フィッシングは例外なく10分間のタイムアウト
                until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)
                await member.timeout(until, reason=reason)
                action_text += " & 10分間タイムアウト"
            except Exception as e:
                action_text += f" (タイムアウト失敗: {e})"

            await send_security_log(
                guild, 
                "🚫 セキュリティリスク(詐欺・リンク)検知",
                "", 
                [
                    ("ユーザー", f"{member.mention} ({member.id})", False),
                    ("理由", reason, False),
                    ("内容", f"||{content_normalized[:100]}||", False),
                    ("処置", action_text, False)
                ], 
                discord.Color.red()
            )
            return

    # ==================================================
    # AntiSpam 検知ロジック
    # ==================================================
    if as_enabled:
        spam_cache_key = (guild.id, member.id, "spam")
        detected_spam = False
        spam_reason = ""

        if len(message.mentions) >= 5:
            detected_spam, spam_reason = True, "メンションスパム検知"

        if not detected_spam:
            cur.execute(
                "INSERT INTO antispam_message_log VALUES (?, ?, ?, ?)",
                (guild.id, member.id, content_raw, now)
            )
            conn.commit()

            cur.execute(
                "SELECT content FROM antispam_message_log WHERE guild_id=? AND user_id=? AND timestamp>=?",
                (guild.id, member.id, now - 10)
            )
            rows = cur.fetchall()

            if len(rows) >= 5:
                detected_spam, spam_reason = True, "短時間メッセージ連投"
            
            if not detected_spam:
                same_count = sum(1 for r in rows if r[0] == content_raw)
                if same_count >= 6:
                    detected_spam, spam_reason = True, "疑似メッセージスパム検知"

            if not detected_spam and ("http://" in content_raw or "https://" in content_raw):
                url_count = sum(1 for r in rows if "http://" in r[0] or "https://" in r[0])
                if url_count >= 5:
                    detected_spam, spam_reason = True, "URL スパム検知"

            if not detected_spam:
                short_urls = ["bit.ly", "tinyurl", "t.co", "is.gd", "goo.gl", "spoo.me"]
                if any(s in content_raw for s in short_urls):
                    short_count = sum(1 for r in rows if any(s in r[0] for s in short_urls))
                    if short_count >= 5:
                        detected_spam, spam_reason = True, "短縮URL スパム検知"

        if detected_spam:
            if spam_cache_key in last_action_cache and now_ts - last_action_cache[spam_cache_key] < 3:
                return
            
            last_action_cache[spam_cache_key] = now_ts
            await safe_delete_message(message, spam_reason)
            await apply_spam_timeout(member, guild, spam_reason)
            return

    # ==================================================
    # コマンド処理
    # ==================================================
    await bot.process_commands(message)

reaction_cache = {}
@bot.event
async def on_raw_reaction_add(payload: discord.RawReactionActionEvent):
    if not payload.guild_id or payload.member.bot:
        return

    guild = bot.get_guild(payload.guild_id)
    member = payload.member
    now = int(time.time())

    # ホワイトリスト除外
    if is_whitelisted_member(member):
        return

    # AntiSpam 有効確認
    cur.execute("SELECT enabled FROM antispam_state WHERE guild_id=?", (guild.id,))
    row = cur.fetchone()
    if not row or row[0] != 1:
        return

    user_id = member.id
    msg_id = payload.message_id
    emoji = str(payload.emoji)

    # 履歴の初期化または更新
    if user_id not in reaction_cache:
        reaction_cache[user_id] = {
            "last_msg_id": 0,
            "current_msg_id": msg_id,
            "last_emojis": [],
            "current_emojis": [emoji],
            "timestamp": now
        }
        return

    data = reaction_cache[user_id]

    # 同じメッセージへの連続追加
    if data["current_msg_id"] == msg_id:
        data["current_emojis"].append(emoji)
        data["timestamp"] = now
    else:
        # 新しいメッセージへの移動
        data["last_msg_id"] = data["current_msg_id"]
        data["last_emojis"] = data["current_emojis"]
        data["current_msg_id"] = msg_id
        data["current_emojis"] = [emoji]
        data["timestamp"] = now

    # ==================================================
    # リアクションスパム判定ロジック
    # ==================================================
    # 条件1: 2つの異なるメッセージに対して
    # 条件2: 直近10秒以内の動作であること
    # 条件3: 3種類以上のリアクションが、前回と全く同じ順番で付与されたこと
    if data["last_msg_id"] != 0 and (now - data["timestamp"]) < 10:
        # 直近の絵文字リストと前回の絵文字リストの「重なり」をチェック
        # （似たようなリアクション＝順番と内容が3つ以上一致）
        common_len = 0
        min_len = min(len(data["last_emojis"]), len(data["current_emojis"]))
        
        for i in range(min_len):
            if data["last_emojis"][i] == data["current_emojis"][i]:
                common_len += 1
            else:
                break # 順番が崩れたら終了

        if common_len >= 3:
            # 🚫 リアクションスパム検知時の処置
            reason = "リアクションスパム検知 (同一パターンの連投)"
            
            # 10分間のタイムアウト適用
            try:
                until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)
                await member.timeout(until, reason=reason)
            except:
                pass

            # 監査ログ送信
            await send_security_log(
                guild,
                "🚫 リアクションスパム検知",
                [
                    ("実行者", f"{member} ({member.id})", False),
                    ("内容", "複数メッセージへの同一パターンリアクション", False),
                    ("処置", "10分間のタイムアウト", False),
                ],
                discord.Color.red()
            )
            # キャッシュクリア
            del reaction_cache[user_id]

# ===============================
# VC 入退室ログ
# ===============================
@bot.event
async def on_voice_state_update(member, before, after):
    guild = member.guild

    if before.channel is None and after.channel is not None:
        action = "🔊 VC参加"
        channel = after.channel.name
    elif before.channel is not None and after.channel is None:
        action = "🔇 VC退出"
        channel = before.channel.name
    else:
        return

    await send_audit_log(
        guild,
        action,
        [
            ("ユーザー", member.mention, True),
            ("チャンネル", channel, True)
        ],
        discord.Color.teal()
    )


# ===============================
# BOT追加ログ
# ===============================
@bot.event
async def on_guild_join(guild):
    # ==========================
    # ブラックリスト照合（最優先）
    # ==========================
    # ブラックリストに載っているか、または期限内であるかを確認
    if is_blacklisted(guild.id):
        try:
            await guild.leave()
            # 退出した場合は以降の処理（DB登録やログ送信）を行わない
            return 
        except Exception as e:
            print(f"[BLACKLIST ERROR][on_guild_join] Failed to leave guild {guild.id}: {repr(e)}")
            # 退出に失敗した場合でも、リスク回避のため以降の処理を中断
            return

    # ==========================
    # AntiNuke 初期DB生成（既存）
    # ==========================
    try:
        cur.execute(
            "INSERT OR IGNORE INTO antinuke_bot (guild_id, enabled) VALUES (?, 0)",
            (guild.id,)
        )
        conn.commit() 
    except Exception as e:
        print("[DB ERROR][on_guild_join]", repr(e))

    # ==========================
    # セキュリティログ送信（Bot追加情報の詳細化）
    # ==========================
    try:
        await send_security_log(
            guild,
            "🤖 BOTが追加されました",
            f"新しいサーバーに {bot.user.name} が導入されました。",
            [
                ("Bot名", f"{bot.user.name} ({bot.user.mention})", False),
                ("Bot ID", str(bot.user.id), False),
                ("サーバー名", guild.name, False),
                ("サーバーID", f"`{guild.id}`", False),
                ("メンバー数", f"{guild.member_count}名", True),
            ],
            discord.Color.green()
        )
    except Exception as e:
        print("[AUDIT LOG ERROR][on_guild_join]", repr(e))

    # ==========================
    # 導入ユーザー（招待者）の特定とDM送信
    # ==========================
    inviter = None
    if guild.me.guild_permissions.view_audit_log:
        try:
            # 監査ログからBot追加（BOT_ADD）の項目を検索
            async for entry in guild.audit_logs(action=discord.AuditLogAction.bot_add, limit=5):
                if entry.target.id == bot.user.id:
                    inviter = entry.user
                    break
        except Exception as e:
            print(f"[AUDIT LOG FETCH ERROR] {e}")

    # 招待者が特定できなかった場合のフォールバック（オーナーに送信）
    if inviter is None:
        inviter = guild.owner

    # 招待者（またはオーナー）にDMを送信
    if inviter:
        try:
            await send_welcome_dm(inviter)
        except Exception as e:
            print(f"[DM ERROR][on_guild_join] {e}")



# ===============================
# メンバー参加（Bot Blacklist + AntiNuke 統合）
# ===============================
@bot.event
async def on_member_join(member: discord.Member):
    guild = member.guild
    if not guild:
        return

    now = asyncio.get_event_loop().time()

    # ==========================================
    # 1. 人間（ユーザー）による参加の場合の Anti-Raid 処理
    # ==========================================
    if not member.bot:
        # DBからAntiRaidが有効かチェック
        cur.execute("SELECT enabled FROM antiraid_settings WHERE guild_id=?", (guild.id,))
        row = cur.fetchone()
        
        if row and row[0] == 1:
            # 15秒以内の参加者をキャッシュして追跡 (タイムスタンプとメンバーオブジェクトを保存)
            join_cache[guild.id] = [item for item in join_cache[guild.id] if now - item[0] < 15]
            join_cache[guild.id].append((now, member))

            join_count = len(join_cache[guild.id])

            # 【追加】15秒間に3人以上参加した場合：警告ログを送信
            if join_count == 3:
                await send_security_log(
                    guild,
                    "⚠️ 参加ペースの上昇を検知",
                    "短時間での連続参加を検知しました。監視を強化しています。",
                    [
                        ("現在のペース", "15秒以内に3名", True),
                        ("ステータス", "注意（監視中）", True)
                    ],
                    discord.Color.gold()
                )

            # 15秒間に5人以上参加した場合：防衛プロトコル発動
            if join_count >= 5:
                # 【修正】キャッシュに溜まっている直近15秒以内のメンバー全員をリスト化して渡す
                target_members = [item[1] for item in join_cache[guild.id]]
                await execute_raid_protection(guild, target_members)
                join_cache[guild.id].clear()
        
        # 人間の通常参加ならここで終了
        return

    # ==========================================
    # 2. Bot による参加の場合の Anti-Nuke / ブラックリスト処理
    # ==========================================
    
    # --- ブラックリスト判定 ---
    cur.execute(
        "SELECT 1 FROM bot_blacklist WHERE bot_id=?",
        (member.id,)
    )
    if cur.fetchone():
        try:
            await member.kick(reason="ブラックリストに登録されているため")
        except:
            pass

        await send_security_log(
            guild,
            "🚫 ブラックリストBOTをKick",
            "システムブラックリストに登録されているBotの侵入を阻止しました。",
            [
                ("対象BOT", f"{member} ({member.id})", False),
                ("実行者", "🛡️ Securo Warden", False),
                ("理由", "ブラックリストに登録されているため", False),
            ],
            discord.Color.red()
        )
        return

    # --- AntiNuke 有効確認 ---
    cur.execute(
        "SELECT enabled FROM antinuke_bot WHERE guild_id=?",
        (guild.id,)
    )
    row_nuke = cur.fetchone()
    if not row_nuke or row_nuke[0] != 1:
        return

    # --- 危険な未認証Bot 判定（エラー修正） ---
    try:
        if member.public_flags.verified_bot:
            return
    except AttributeError:
        return

    # --- 招待者特定 ---
    inviter = None
    if guild.me.guild_permissions.view_audit_log:
        try:
            async for entry in guild.audit_logs(limit=5, action=discord.AuditLogAction.bot_add):
                if entry.target.id == member.id:
                    inviter = entry.user
                    break
        except:
            pass

    # ホワイトリスト招待者は除外
    if inviter and isinstance(inviter, discord.Member):
        if is_whitelisted_member(inviter):
            return

    # --- Webhook 全削除（API高負荷バグ修正：1回で全取得して処理） ---
    if guild.me.guild_permissions.manage_webhooks:
        try:
            all_webhooks = await guild.webhooks()
            for webhook in all_webhooks:
                await webhook.delete(reason="AntiNuke: 未認証Bot検知に伴う一括削除")
        except:
            pass

    # --- Bot Kick ---
    try:
        await guild.kick(member, reason="AntiNuke: 未認証Bot検知")
    except:
        pass

    # --- 招待者 BAN ---
    if inviter:
        try:
            await guild.ban(inviter, reason="AntiNuke: 未認証Botを招待")
        except:
            pass

    # --- ロックダウン（全チャンネル） & バックアップ ---
    cur.execute("DELETE FROM antinuke_backup WHERE guild_id=?", (guild.id,))

    for channel in guild.text_channels:
        perms = channel.permissions_for(guild.me)
        if perms.manage_roles:
            overwrite = channel.overwrites_for(guild.default_role)

            # バックアップ保存
            cur.execute(
                "INSERT INTO antinuke_backup (guild_id, channel_id, role_id, allow_send) VALUES (?, ?, ?, ?)",
                (
                    guild.id,
                    channel.id,
                    guild.default_role.id,
                    int(overwrite.send_messages is not False)
                )
            )

            overwrite.send_messages = False
            try:
                await channel.set_permissions(guild.default_role, overwrite=overwrite, reason="AntiNuke: 緊急隔離")
            except:
                pass

    conn.commit()

    # --- 招待リンク削除 ---
    try:
        invites = await guild.invites()
        for invite in invites:
            await invite.delete(reason="AntiNuke 発動")
    except:
        pass

    # --- 監査ログ送信 ---
    await send_security_log(
        guild,
        "🧨 AntiNuke 発動",
        "危険なBotの侵入を検知しました",
        [
            ("侵入Bot", f"{member} ({member.id})", False),
            ("招待者", f"{inviter} ({inviter.id})" if inviter else "不明", False),
            ("処理内容", "Webhook削除 / Bot Kick / 招待者BAN / Lockdown", False),
        ],
        discord.Color.dark_red()
    )

    # --- 自動復旧（30秒後） ---
    await asyncio.sleep(30)

    cur.execute(
        "SELECT channel_id, allow_send FROM antinuke_backup WHERE guild_id=?",
        (guild.id,)
    )
    rows = cur.fetchall()

    for channel_id, allow in rows:
        target_channel = guild.get_channel(channel_id)
        if not target_channel:
            continue

        perms = target_channel.permissions_for(guild.me)
        if perms.manage_roles:
            overwrite = target_channel.overwrites_for(guild.default_role)
            # バックアップ時の状態に基づき復旧
            overwrite.send_messages = bool(allow) if allow else None
            try:
                await target_channel.set_permissions(guild.default_role, overwrite=overwrite, reason="AntiNuke: 自動復旧")
            except:
                pass

    cur.execute("DELETE FROM antinuke_backup WHERE guild_id=?", (guild.id,))
    conn.commit()

# ===============================
# チャンネル削除検知
# ===============================
@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    guild = channel.guild
    now = int(time.time())

    if guild is None:
        return

    # ===============================
    # AntiNuke 有効確認
    # ===============================
    cur.execute(
        "SELECT enabled FROM antinuke_bot WHERE guild_id=?",
        (guild.id,)
    )
    row = cur.fetchone()
    if not row or row[0] != 1:
        return

    # ===============================
    # 犯人特定（そのまま）
    # ===============================
    executor = await fetch_channel_delete_executor(
        guild,
        channel.id
    )
    if executor is None:
        return

    member = guild.get_member(executor.id)
    if member is None or is_whitelisted_member(member):
        return

    # ===============================
    # カテゴリ削除
    # ===============================
    if isinstance(channel, discord.CategoryChannel):
        asyncio.create_task(
            trigger_antinuke(
                guild,
                reason=f"カテゴリ削除検知（{member}）"
            )
        )

        asyncio.create_task(
            guild.ban(
                member,
                reason="AntiNuke: カテゴリ削除"
            )
        )

        asyncio.create_task(
            send_security_log(
                guild,
                "🧨 AntiNuke: カテゴリ削除",
                [
                    ("実行者", f"{member} ({member.id})", False),
                    ("カテゴリ名", channel.name, False),
                ],
                discord.Color.dark_red()
            )
        )
        return

    # ===============================
    # Alert Mode（変更なし）
    # ===============================
    alert = get_alert_mode(guild)
    threshold, window = (
        (1, 5) if alert == "high"
        else (2, 5) if alert == "medium"
        else (3, 10)
    )

    # ===============================
    # カウント
    # ===============================
    cur.execute(
        """
        SELECT deleted_count, last_updated
        FROM antinuke_channel_user_counter
        WHERE guild_id=? AND user_id=?
        """,
        (guild.id, member.id)
    )
    row = cur.fetchone()

    if row:
        count, last = row
        count = count + 1 if now - last <= window else 1
    else:
        count = 1

    cur.execute(
        """
        INSERT OR REPLACE INTO antinuke_channel_user_counter
        VALUES (?, ?, ?, ?)
        """,
        (guild.id, member.id, count, now)
    )
    conn.commit()

    if count < threshold:
        return

    # ===============================
    # 発動 & BAN（並列）
    # ===============================
    asyncio.create_task(
        trigger_antinuke(
            guild,
            reason=f"チャンネル削除 {count}件 / {window}秒（{member}）"
        )
    )

    asyncio.create_task(
        guild.ban(
            member,
            reason="AntiNuke: チャンネル大量削除"
        )
    )

    asyncio.create_task(
        send_security_log(
            guild,
            "🔨 AntiNuke: チャンネル削除者BAN",
            [
                ("対象ユーザー", f"{member} ({member.id})", False),
                ("削除回数", f"{count} / {window}秒", False),
                ("警戒モード", alert.upper(), False),
            ],
            discord.Color.dark_red()
        )
    )

@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    guild = after.guild

    # ===============================
    # Perm Guard 有効確認
    # ===============================
    cur.execute(
        "SELECT enabled, quarantine_role_id FROM perm_guard WHERE guild_id=?",
        (guild.id,)
    )
    row = cur.fetchone()
    if not row or row[0] != 1:
        return

    quarantine_role_id = row[1]

    before_roles = {r.id for r in before.roles}
    after_roles = {r.id for r in after.roles}

    added_roles = [
        guild.get_role(rid)
        for rid in (after_roles - before_roles)
    ]

    # 危険ロールが複数付与されたか
    dangerous_roles = [
        r for r in added_roles
        if r and is_dangerous_role(r)
    ]

    if len(dangerous_roles) < 2:
        return

    # ===============================
    # Audit Log で付与者特定
    # ===============================
    executor = None
    async for entry in guild.audit_logs(
        limit=5,
        action=discord.AuditLogAction.member_role_update
    ):
        if entry.target.id == after.id:
            executor = entry.user
            break

    # ===============================
    # 権限剥奪 + 隔離
    # ===============================
    try:
        await after.remove_roles(
            *dangerous_roles,
            reason="Perm Guard: 危険権限剥奪"
        )
    except:
        pass

    quarantine_role = guild.get_role(quarantine_role_id)
    if quarantine_role:
        try:
            await after.add_roles(
                quarantine_role,
                reason="Perm Guard: 隔離"
            )
        except:
            pass

    # ===============================
    # 実行者BAN（BOT含む）
    # ===============================
    if executor:
        try:
            await guild.ban(
                executor,
                reason="Perm Guard: 危険ロール一括付与"
            )
        except:
            pass

    # ===============================
    # 監査ログ
    # ===============================
    await send_security_log(
        guild,
        "🚨 Perm Guard 発動",
        [
            ("対象メンバー", f"{after} ({after.id})", False),
            ("付与ロール", ", ".join(r.name for r in dangerous_roles), False),
            ("実行者", f"{executor} ({executor.id})" if executor else "不明", False),
            ("処理", "権限剥奪 / 隔離 / 実行者BAN", False),
        ],
        discord.Color.dark_red()
    )

@bot.event
async def on_invite_create(invite: discord.Invite):
    guild = invite.guild
    if not guild:
        return

    # ===============================
    # Invite SafeMode 有効確認
    # ===============================
    cur.execute(
        "SELECT enabled FROM invite_safemode WHERE guild_id=?",
        (guild.id,)
    )
    row = cur.fetchone()
    if not row or row[0] != 1:
        return

    # ===============================
    # 招待者特定
    # ===============================
    inviter = invite.inviter
    if not inviter or not isinstance(inviter, discord.Member):
        return

    # ===============================
    # whitelist 除外
    # ===============================
    if is_whitelisted_member(inviter):
        return

    now = int(time.time())

    # ===============================
    # ログ保存
    # ===============================
    cur.execute(
        "INSERT INTO invite_create_log VALUES (?, ?, ?)",
        (guild.id, inviter.id, now)
    )
    conn.commit()

    # ===============================
    # 短時間大量作成検知（10秒で3回）
    # ===============================
    cur.execute(
        """
        SELECT 1 FROM invite_create_log
        WHERE guild_id=? AND user_id=? AND created_at>=?
        """,
        (guild.id, inviter.id, now - 10)
    )
    rows = cur.fetchall()

    if len(rows) < 3:
        return

    # ===============================
    # ★ 新規招待作成をブロック
    # ===============================
    try:
        for channel in guild.text_channels:
            overwrite = channel.overwrites_for(guild.default_role)
            overwrite.create_instant_invite = False
            await channel.set_permissions(
                guild.default_role,
                overwrite=overwrite,
                reason="Invite SafeMode: 招待大量作成検知"
            )
    except:
        pass

    # ===============================
    # 招待削除
    # ===============================
    try:
        invites = await guild.invites()
        for inv in invites:
            if inv.inviter == inviter:
                await inv.delete(reason="Invite SafeMode: 招待大量作成")
    except:
        pass

    # ===============================
    # Audit Log
    # ===============================
    await send_security_log(
        guild,
        "🔗 招待リンク大量作成検知",
        [
            ("実行者", f"{inviter} ({inviter.id})", False),
            ("処理内容", "招待作成ブロック / 招待削除", False),
        ],
        discord.Color.orange()
    )

@bot.event
async def on_webhooks_update(channel: discord.abc.GuildChannel):
    guild = channel.guild
    if not guild:
        return

    # ===============================
    # 直近のWebhook監査ログ取得
    # ===============================
    try:
        async for entry in guild.audit_logs(limit=3):
            if entry.action not in (
                discord.AuditLogAction.webhook_create,
                discord.AuditLogAction.webhook_delete,
                discord.AuditLogAction.webhook_update
            ):
                continue

            executor = entry.user
            target = entry.target  # Webhook

            # Bot自身の操作は除外
            if executor and executor.id == guild.me.id:
                return

            # whitelist 除外
            if isinstance(executor, discord.Member):
                if is_whitelisted_member(executor):
                    return

            # ===============================
            # 操作種別
            # ===============================
            if entry.action == discord.AuditLogAction.webhook_create:
                title = "🪝 Webhook 作成検知"
                color = discord.Color.green()
                action_text = "Webhook 作成"

            elif entry.action == discord.AuditLogAction.webhook_delete:
                title = "🪝 Webhook 削除検知"
                color = discord.Color.red()
                action_text = "Webhook 削除"

            else:
                title = "🪝 Webhook 編集検知"
                color = discord.Color.orange()
                action_text = "Webhook 編集"

            # ===============================
            # 変更内容（名前・アイコン）
            # ===============================
            changes = []
            try:
                for change in entry.changes:
                    if change.attribute in ("name", "avatar"):
                        before = str(change.before)
                        after = str(change.after)
                        changes.append(
                            f"{change.attribute}: {before} → {after}"
                        )
            except:
                pass

            change_text = "\n".join(changes) if changes else "なし"

            # ===============================
            # Audit Log 送信
            # ===============================
            try:
                await send_security_log(
                    guild,
                    title,
                    [
                        ("実行者", f"{executor} ({executor.id})", False),
                        ("Webhook", target.name if target else "不明", False),
                        ("操作", action_text, False),
                        ("変更内容", change_text[:1024], False),
                        ("チャンネル", channel.mention, False),
                    ],
                    color
                )
            except:
                pass

            return  # 二重送信防止
    except:
        pass

@bot.event
async def on_audit_log_entry_create(entry):
    # 自分の操作（Bot自身が行った操作）は記録しない
    if entry.user and entry.user.id == bot.user.id:
        return

    guild = entry.guild
    if not guild:
        return

    # 1. 管理者権限(Administrator)の付与検知
    if entry.action == discord.AuditLogAction.member_role_update:
        # roles属性が存在するかチェック（getattrで安全に取得）
        before_roles = getattr(entry.before, 'roles', [])
        after_roles = getattr(entry.after, 'roles', [])
        
        # 追加されたロールを特定
        added_roles = [role for role in after_roles if role not in before_roles]
        
        for role in added_roles:
            if role.permissions.administrator:
                await send_security_log(
                    guild,
                    "⚠️ 管理権限付与を検知",
                    f"ユーザーに管理者権限が付与されました。乗っ取りの可能性があるため確認してください。",
                    [("対象者", entry.target.mention if entry.target else "不明", True), 
                     ("実行者", entry.user.mention if entry.user else "不明", True)],
                    color=discord.Color.red()
                )

    # 2. ロールの階層順序（位置）変更検知
    elif entry.action == discord.AuditLogAction.role_update:
        # before/afterにposition属性が存在する場合のみ比較を実行
        before_pos = getattr(entry.before, 'position', None)
        after_pos = getattr(entry.after, 'position', None)

        if before_pos is not None and after_pos is not None:
            if before_pos != after_pos:
                await send_security_log(
                    guild,
                    "🛡️ ロール位置変更を検知",
                    f"ロールの並び順が変更されました。権限付与乗っ取りの予兆である可能性があります。",
                    [("対象ロール", entry.target.name if entry.target else "不明", True), 
                     ("実行者", entry.user.mention if entry.user else "不明", True)],
                    color=discord.Color.orange()
                )

# --- 1日の統計レポート (日本時間 23:59 送信) ---
# datetime.datetime と datetime.time の競合を避けるため
# 呼び出しを time(...) に修正しています
# 名前衝突を避けるため、dt_time を使用
@tasks.loop(time=dt_time(hour=23, minute=59, tzinfo=JST))
async def daily_stats_report():
    """
    1日の統計レポートを全サーバーへ送信し、古いデータをクリーンアップする。
    """
    
    # 1. 古い統計データのクリーンアップ
    try:
        cur.execute("DELETE FROM daily_incidents WHERE timestamp < datetime('now', '-7 days')")
        conn.commit()
    except Exception as e:
        print(f"[ERROR][Cleanup] {e}")

    # 2. 設定が有効なギルド一覧を取得
    try:
        cur.execute("SELECT DISTINCT guild_id FROM security_settings")
        guilds = cur.fetchall()
    except Exception as e:
        print(f"[ERROR][Database] Failed to fetch guilds: {e}")
        return

    for (guild_id,) in guilds:
        guild = bot.get_guild(guild_id)
        if not guild:
            continue

        try:
            # 過去24時間のインシデントを取得
            cur.execute("""
                SELECT event_type FROM daily_incidents 
                WHERE guild_id = ? AND timestamp > datetime('now', '-1 day')
            """, (guild_id,))
            rows = cur.fetchall()

            incident_count = len(rows)
            # 安全スコア算出
            safety_score = max(0, 100 - (incident_count * 10))
            
            # 重複を除いたインシデント名の抽出
            incident_names = list(set([r[0] for r in rows]))
            incident_display = ", ".join(incident_names) if incident_names else "なし"

            # 安全度に応じた推奨対応の分岐
            if safety_score == 100:
                advice = "サーバーは非常に健全な状態です。現在のセキュリティ設定を維持してください。"
            elif safety_score >= 70:
                advice = "いくつかの軽微な脅威をブロックしました。最近参加したユーザーやBotを再点検してください。"
            else:
                advice = "【緊急】深刻なリスクを多数検知しました。全ロール権限の緊急監査を強く推奨します。"

            # セキュリティログ送信関数を呼び出し
            # 引数末尾に is_incident=False を追加して、この送信自体をカウント対象から外す
            await send_security_log(
                guild,
                "📊 今日１日の統計",
                "本日のサーバーセキュリティ稼働レポートです。",
                [
                    ("インシデント内容", incident_display, False),
                    ("サーバーの安全性", f"**{safety_score}/100**", True),
                    ("推奨対応", advice, False)
                ],
                color=discord.Color.blue(),
                is_incident=False # ← ここが最重要の修正点です
            )
        except Exception as e:
            print(f"[ERROR][daily_stats_report] Guild: {guild_id} - {e}")

@bot.event
async def on_app_command_completion(interaction: discord.Interaction, command):
    try:
        guild = interaction.guild
        channel = interaction.channel

        # ==================================================
        # 📝 オプション解析ロジック
        # ==================================================
        options_text = "オプション なし"
        if interaction.data and 'options' in interaction.data:
            opts = interaction.data.get('options', [])
            if opts:
                options_list = []
                for opt in opts:
                    name = opt.get('name')
                    value = opt.get('value')
                    options_list.append(f"{name}:{value}")
                options_text = "\n".join(options_list)

        await send_security_webhook(
            "🧾 コマンド実行",
            [
                ("👤 実行者", f"{interaction.user} ({interaction.user.id})", False),
                ("⌨️ コマンド", f"/{command.name}", False),
                ("⚙️ オプション", options_text, False), # オプションを表示
                ("🏠 サーバー", f"{guild.name} ({guild.id})" if guild else "DM", False),
                ("📍 チャンネル", f"{channel.name} ({channel.id})" if channel else "不明", False),
            ],
            0x5865F2
        )

    except Exception as e:
        logging.error(f"Command Log Error: {e}")

async def global_check(interaction: discord.Interaction):

    # 管理者コマンドはバイパス (コマンド実行時のみチェック)
    if interaction.command and interaction.command.name.startswith("admin_"):
        return True

    # ======================
    # 利用停止チェック (ボタン操作もここでストップします)
    # ======================

    if await check_admin_penalty(interaction):

        embed = discord.Embed(
            title="🚫 利用停止中",
            description="あなたは現在 **Securo Warden** を利用停止されています。",
            color=discord.Color.red()
        )

        if interaction.response.is_done():
            await interaction.followup.send(embed=embed, ephemeral=True)
        else:
            await interaction.response.send_message(embed=embed, ephemeral=True)

        return False

    # ======================
    # 規約チェック
    # ======================

    try:

        cur.execute("SELECT version FROM terms_current LIMIT 1")
        current_version = cur.fetchone()[0]

        cur.execute(
            "SELECT version FROM terms_agreed WHERE user_id=?",
            (interaction.user.id,)
        )

        row = cur.fetchone()

        if not row or row[0] != current_version:

            embed = create_terms_embed()
            view = TermsView()

            if interaction.response.is_done():
                await interaction.followup.send(embed=embed, view=view, ephemeral=True)
            else:
                await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

            return False

    except Exception as e:
        print("terms check error:", e)

    return True

# ★ここが最重要
bot.tree.interaction_check = global_check

# ===============================
# PING
# ===============================
@bot.tree.command(name="ping", description="BOTの応答速度を表示します")
async def ping(interaction: discord.Interaction):
    start = time.perf_counter()
    await interaction.response.defer(ephemeral=False)
    elapsed = round((time.perf_counter() - start) * 1000)
    ws_latency = round(bot.latency * 1000)

    await interaction.followup.send(
        f"🏓 Pong! **{ws_latency}ms** (Response: {elapsed}ms)",
        ephemeral=False
    )


# ===============================
# BAN
# ===============================
@bot.tree.command(
    name="ban",
    description="ユーザーをBANします（期間指定可・未入力で永久BAN）"
)
@app_commands.checks.has_permissions(ban_members=True)
async def ban(
    interaction: discord.Interaction,
    user: discord.User,
    reason: str | None = None,
    duration: str | None = None,
    dm: bool = True
):
    # 権限チェック（手動表示用）
    if not interaction.user.guild_permissions.ban_members:
        await interaction.response.send_message("❌ このコマンドを実行するには**メンバーをBAN**権限が必要です。", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)
    guild = interaction.guild
    ban_reason = reason if reason else "理由が入力されていません"

    seconds = parse_duration(duration)
    is_permanent = duration is None

    if duration is not None and seconds is None:
        await interaction.followup.send(
            "❌ 期間の形式が正しくありません（例: 10s, 5m, 2h, 1d）",
            ephemeral=True
        )
        return

    try:
        await guild.ban(user, reason=ban_reason)
    except discord.Forbidden:
        await interaction.followup.send(
            "❌ このコマンドを実行するには**メンバーをBAN**権限が必要です。",
            ephemeral=True
        )
        return
    except discord.HTTPException:
        await interaction.followup.send(
            "❌ BANに失敗しました（Discord側エラー）。",
            ephemeral=True
        )
        return

    if dm:
        embed = discord.Embed(
            title="🚫 サーバーからBANされました",
            color=discord.Color.red()
        )
        embed.add_field(name="サーバー", value=guild.name, inline=False)
        embed.add_field(name="理由", value=ban_reason, inline=False)
        embed.add_field(
            name="期間",
            value="永久" if is_permanent else duration,
            inline=False
        )
        try:
            await user.send(embed=embed)
        except:
            pass

    if not is_permanent:
        unban_time = int(time.time()) + seconds
        cur.execute(
            "INSERT OR REPLACE INTO temp_bans VALUES (?, ?, ?, ?)",
            (user.id, guild.id, unban_time, ban_reason)
        )
        conn.commit()

    log_user_action(
        guild_id=guild.id,
        action="ban",
        executor_id=interaction.user.id,
        target_id=user.id,
        extra={
            "duration": "permanent" if is_permanent else duration,
            "reason": ban_reason
        }
    )

    await send_security_log(
        guild,
        "🔨 BAN",
        [
            ("対象ユーザー", f"{user} ({user.id})", False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("期間", "永久" if is_permanent else duration, False),
            ("理由", ban_reason, False),
        ],
        discord.Color.red()
    )
    await send_security_webhook(
        "🔨 BAN 実行",
        [
            ("サーバー", f"{guild.name} ({guild.id})", False),
            ("対象", f"{user} ({user.id})", False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("期間", "永久" if is_permanent else duration, False),
            ("理由", ban_reason, False),
        ],
        0xff0000
    )

    await interaction.followup.send(
        f"✅ {user.mention} をBANしました。",
        ephemeral=True
    )

# UNBAN
@bot.tree.command(name="unban", description="ユーザーのBANを解除します")
@app_commands.checks.has_permissions(ban_members=True)
async def unban(
    interaction: discord.Interaction,
    user: discord.User,
    reason: str | None = None,
    dm: bool = True
):
    if not interaction.user.guild_permissions.ban_members:
        await interaction.response.send_message("❌ このコマンドを実行するには**メンバーをBAN**権限が必要です。", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)
    guild = interaction.guild
    unban_reason = reason if reason else "理由が入力されていません"

    try:
        await guild.unban(user, reason=unban_reason)
    except:
        await interaction.followup.send("❌ BAN解除に失敗しました。対象がBANリストにいない可能性があります。", ephemeral=True)
        return

    log_user_action(
        guild_id=guild.id,
        action="unban",
        executor_id=interaction.user.id,
        target_id=user.id,
        extra={"reason": unban_reason}
    )

    cur.execute(
        "DELETE FROM temp_bans WHERE user_id=? AND guild_id=?",
        (user.id, guild.id)
    )
    conn.commit()

    if dm:
        embed = discord.Embed(
            title="✅ BAN解除通知",
            color=discord.Color.green()
        )
        embed.description = (
            f"あなたは **{guild.name}** からBanが解除されました\n\n"
            f"理由:\n{unban_reason}"
        )
        try:
            await user.send(embed=embed)
        except:
            pass

    await send_security_log(
        guild,
        "✅ BAN解除",
        [
            ("対象ユーザー", f"{user} ({user.id})", False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("理由", unban_reason, False),
        ],
        discord.Color.green()
    )
    await send_security_webhook(
        "✅ UNBAN 実行",
        [
            ("サーバー", f"{guild.name} ({guild.id})", False),
            ("対象", f"{user} ({user.id})", False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("理由", unban_reason, False),
        ],
        0x00ff00
    )

    await interaction.followup.send(
        f"✅ {user.mention} のBANを解除しました。",
        ephemeral=True
    )

# KICK
@bot.tree.command(name="kick", description="ユーザーをKickします")
@app_commands.checks.has_permissions(kick_members=True)
async def kick(
    interaction: discord.Interaction,
    user: discord.Member,
    reason: str | None = None,
    dm: bool = True
):
    if not interaction.user.guild_permissions.kick_members:
        await interaction.response.send_message("❌ このコマンドを実行するには**メンバーをキック**権限が必要です。", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)
    guild = interaction.guild
    kick_reason = reason if reason else "理由が入力されていません"

    if dm:
        embed = discord.Embed(
            title="👢 サーバーからKickされました",
            color=discord.Color.orange()
        )
        embed.add_field(name="サーバー", value=guild.name, inline=False)
        embed.add_field(name="理由", value=kick_reason, inline=False)
        try:
            await user.send(embed=embed)
        except:
            pass

    try:
        await guild.kick(user, reason=kick_reason)
    except:
        await interaction.followup.send("❌ Kickに失敗しました。", ephemeral=True)
        return

    log_user_action(
        guild_id=guild.id,
        action="kick",
        executor_id=interaction.user.id,
        target_id=user.id,
        extra={"reason": kick_reason}
    )

    await send_security_log(
        guild,
        "👢 Kick",
        [
            ("対象ユーザー", f"{user} ({user.id})", False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("理由", kick_reason, False),
        ],
        discord.Color.orange()
    )
    await send_security_webhook(
        "👢 KICK 実行",
        [
            ("サーバー", f"{guild.name} ({guild.id})", False),
            ("対象", f"{user} ({user.id})", False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("理由", kick_reason, False),
        ],
        0xff8800
    )

    await interaction.followup.send(
        f"✅ {user.mention} をKickしました。",
        ephemeral=True
    )

# --- Purge Group 登録 ---
purge_group = app_commands.Group(name="purge", description="メッセージ一括削除コマンド")

@purge_group.command(name="messages", description="指定した数のメッセージを削除します")
@app_commands.describe(count="削除する数 (2-1000)")
async def purge_messages(
    interaction: discord.Interaction,
    count: app_commands.Range[int, 2, 1000]
):
    # interaction_check で権限確認済み
    await interaction.response.defer(ephemeral=True)
    channel = interaction.channel
    view = PurgeConfirmView(interaction.user.id)

    await interaction.followup.send(
        f"⚠️ **メッセージ削除の確認**\n\n"
        f"チャンネル：{channel.mention}\n"
        f"削除予定数：{count} 件\n\n"
        f"この操作は取り消せません。",
        view=view,
        ephemeral=True
    )

    await view.wait()
    if not view.confirmed:
        await interaction.followup.send("❌ purge はキャンセルされました。", ephemeral=True)
        return

    deleted = await channel.purge(limit=count)

    log_user_action(
        guild_id=interaction.guild.id,
        action="purge",
        executor_id=interaction.user.id,
        extra={"channel_id": channel.id, "count": len(deleted)}
    )

    await send_security_log(
        interaction.guild,
        "🧹 メッセージ一括削除",
        [
            ("チャンネル", channel.mention, False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("削除数", str(len(deleted)), False),
        ],
        discord.Color.orange()
    )
    await interaction.followup.send(f"✅ {len(deleted)} 件のメッセージを削除しました。", ephemeral=True)

@purge_group.command(name="keyword", description="指定したキーワードを含むメッセージを削除します")
@app_commands.describe(keyword="削除対象のキーワード")
async def purge_keyword(
    interaction: discord.Interaction,
    keyword: str
):
    await interaction.response.defer(ephemeral=True)
    channel = interaction.channel

    deleted = []
    async for msg in channel.history(limit=1000):
        if msg.created_at < discord.utils.utcnow() - timedelta(days=14):
            break
        if keyword in msg.content:
            deleted.append(msg)

    view = PurgeConfirmView(interaction.user.id)
    await interaction.followup.send(
        f"⚠️ **キーワード削除の確認**\n\n"
        f"チャンネル：{channel.mention}\n"
        f"キーワード：`{keyword}`\n"
        f"削除予定数：{len(deleted)} 件\n\n"
        f"この操作は取り消せません。",
        view=view,
        ephemeral=True
    )

    await view.wait()
    if not view.confirmed:
        await interaction.followup.send("❌ キーワード purge はキャンセルされました。", ephemeral=True)
        return

    if deleted:
        # 14日以内のメッセージのみ一括削除可能
        await channel.delete_messages(deleted)

    await send_security_log(
        interaction.guild,
        "🔍 キーワード削除",
        [
            ("チャンネル", channel.mention, False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("キーワード", keyword, False),
            ("削除数", str(len(deleted)), False),
        ],
        discord.Color.dark_orange()
    )

    await interaction.followup.send(f"✅ {len(deleted)} 件のメッセージを削除しました。", ephemeral=True)

    log_user_action(
        action="purge_keyword",
        guild_id=interaction.guild.id,
        executor_id=interaction.user.id,
        target_id=None,
        extra={
            "keyword": keyword,
            "deleted_count": len(deleted),
            "channel_id": interaction.channel.id
        }
    )

# ツリーにグループを追加
bot.tree.add_command(purge_group)


# ===============================
# TIMEOUT
# ===============================
timeout_group = app_commands.Group(name="timeout", description="タイムアウト関連のコマンド")

@timeout_group.command(name="add", description="ユーザーをタイムアウトします")
@app_commands.checks.has_permissions(moderate_members=True)
async def timeout_add(
    interaction: discord.Interaction,
    user: discord.Member,
    duration: str,
    reason: str | None = None
):
    # 権限チェック
    if not interaction.user.guild_permissions.moderate_members:
        await interaction.response.send_message("❌ このコマンドを実行するには**メンバーをタイムアウト**権限が必要です。", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)
    
    seconds = parse_duration(duration)
    if seconds is None:
        await interaction.followup.send(
            "❌ 期間の形式が正しくありません。",
            ephemeral=True
        )
        return

    until = discord.utils.utcnow() + timedelta(seconds=seconds)
    timeout_reason = reason if reason else "理由が入力されていません"

    await user.timeout(until, reason=timeout_reason)
    
    log_user_action(
        guild_id=interaction.guild.id,
        action="timeout",
        executor_id=interaction.user.id,
        target_id=user.id,
        extra={
            "duration": duration,
            "reason": timeout_reason
        }
    )

    await send_security_log(
        interaction.guild,
        "⏱️ タイムアウト実行",
        [
            ("対象ユーザー", f"{user} ({user.id})", False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("期間", duration, False),
            ("理由", timeout_reason, False),
        ],
        discord.Color.dark_orange()
    )
    
    await send_security_webhook(
        "⏱️ TIMEOUT 実行",
        [
            ("サーバー", f"{interaction.guild.name} ({interaction.guild.id})", False),
            ("対象", f"{user} ({user.id})", False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("期間", duration, False),
            ("理由", timeout_reason, False),
        ],
        0xffaa00
    )

    await interaction.followup.send(
        f"✅ {user.mention} を {duration} タイムアウトしました。",
        ephemeral=True
    )

@timeout_group.command(name="remove", description="ユーザーのタイムアウトを解除します")
@app_commands.checks.has_permissions(moderate_members=True)
async def timeout_remove(
    interaction: discord.Interaction,
    user: discord.Member,
    reason: str | None = None
):
    # 権限チェック
    if not interaction.user.guild_permissions.moderate_members:
        await interaction.response.send_message("❌ このコマンドを実行するには**メンバーをタイムアウト**権限が必要です。", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)

    if user.timed_out_until is None:
        await interaction.followup.send(
            "❌このユーザーはタイムアウトされていません。",
            ephemeral=True
        )
        return

    cancel_reason = reason if reason else "解除理由は入力されていません"

    await user.timeout(None, reason=cancel_reason)
    
    log_user_action(
        guild_id=interaction.guild.id,
        action="cancel_timeout",
        executor_id=interaction.user.id,
        target_id=user.id,
        extra={
            "reason": cancel_reason
        }
    )

    await send_security_log(
        interaction.guild,
        "⏱️ タイムアウト解除",
        [
            ("対象ユーザー", f"{user} ({user.id})", False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("理由", cancel_reason, False),
        ],
        discord.Color.green()
    )
    
    await send_security_webhook(
        "⏱️ TIMEOUT 解除",
        [
            ("サーバー", f"{interaction.guild.name} ({interaction.guild.id})", False),
            ("対象", f"{user} ({user.id})", False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("理由", cancel_reason, False),
        ],
        0x00cc66
    )

    await interaction.followup.send(
        f"✅ {user.mention} のタイムアウトを解除しました。",
        ephemeral=True
    )

bot.tree.add_command(timeout_group)

@bot.tree.command(name="auditlog_channel", description="BOTの監査ログを投稿するチャンネルを設定します")
async def audit_log_channel(
    interaction: discord.Interaction,
    channel: discord.TextChannel
):
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message("❌ このコマンドを実行するには**サーバー管理**権限が必要です。", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)

    cur.execute(
        """
        INSERT OR REPLACE INTO audit_log_channel
        (guild_id, channel_id)
        VALUES (?, ?)
        """,
        (interaction.guild.id, channel.id)
    )
    conn.commit()

    await interaction.followup.send(
        f"✅ 監査ログ投稿先を {channel.mention} に設定しました。これ以降、Webhook経由でログが送信されます。",
        ephemeral=True
    )

    await send_security_log(
        interaction.guild,
        "⚙️ 監査ログチャンネル変更",
        [
            ("サーバー", f"{interaction.guild.name} ({interaction.guild.id})", False),
            ("新チャンネル", f"{channel.name} ({channel.id})", False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
        ],
        discord.Color.from_rgb(51, 102, 255)
    )

# ===============================
# WHITELIST GROUP
# ===============================
whitelist_group = app_commands.Group(name="whitelist", description="ホワイトリスト関連のコマンド")

@whitelist_group.command(name="add_user", description="指定したユーザーをホワイトリストに追加します")
@app_commands.checks.has_permissions(manage_guild=True)
async def whitelist_add_user(
    interaction: discord.Interaction,
    user: discord.Member
):
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message("❌ このコマンドを実行するには**サーバー管理**権限が必要です。", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)

    cur.execute(
        "INSERT OR IGNORE INTO whitelist_users VALUES (?, ?)",
        (interaction.guild.id, user.id)
    )
    conn.commit()

    await interaction.followup.send(
        f"✅ {user.mention} をホワイトリストに追加しました。",
        ephemeral=True
    )

    await send_security_webhook(
        "🛡️ ホワイトリスト追加",
        [
            ("サーバー", f"{interaction.guild.name} ({interaction.guild.id})", False),
            ("対象", f"{user} ({user.id})", False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
        ],
        0x0099ff
    )

@whitelist_group.command(name="add_role", description="指定したロールをホワイトリストに追加します")
@app_commands.checks.has_permissions(manage_guild=True)
async def whitelist_add_role(
    interaction: discord.Interaction,
    role: discord.Role
):
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message("❌ このコマンドを実行するには**サーバー管理**権限が必要です。", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)

    cur.execute(
        "INSERT OR IGNORE INTO whitelist_roles VALUES (?, ?)",
        (interaction.guild.id, role.id)
    )
    conn.commit()

    await interaction.followup.send(
        f"✅ ロール **{role.name}** をホワイトリストに追加しました。",
        ephemeral=True
    )

    await send_security_webhook(
        "🛡️ ホワイトリスト追加（ロール）",
        [
            ("サーバー", f"{interaction.guild.name} ({interaction.guild.id})", False),
            ("対象ロール", f"{role.name} ({role.id})", False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
        ],
        0x0099ff
    )

@whitelist_group.command(name="remove_user", description="指定したユーザーをホワイトリストから削除します")
@app_commands.checks.has_permissions(manage_guild=True)
async def whitelist_remove_user(
    interaction: discord.Interaction,
    user: discord.Member
):
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message("❌ このコマンドを実行するには**サーバー管理**権限が必要です。", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)

    cur.execute(
        "DELETE FROM whitelist_users WHERE guild_id=? AND user_id=?",
        (interaction.guild.id, user.id)
    )
    conn.commit()

    await interaction.followup.send(
        f"🗑️ {user.mention} をホワイトリストから削除しました。",
        ephemeral=True
    )

    await send_security_webhook(
        "🛡️ ホワイトリスト削除",
        [
            ("サーバー", f"{interaction.guild.name} ({interaction.guild.id})", False),
            ("対象", f"{user} ({user.id})", False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
        ],
        0x0099ff
    )

@whitelist_group.command(name="remove_role", description="指定したロールをホワイトリストから削除します")
@app_commands.checks.has_permissions(manage_guild=True)
async def whitelist_remove_role(
    interaction: discord.Interaction,
    role: discord.Role
):
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message("❌ このコマンドを実行するには**サーバー管理**権限が必要です。", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)

    cur.execute(
        "DELETE FROM whitelist_roles WHERE guild_id=? AND role_id=?",
        (interaction.guild.id, role.id)
    )
    conn.commit()

    await interaction.followup.send(
        f"🗑️ ロール **{role.name}** をホワイトリストから削除しました。",
        ephemeral=True
    )

    await send_security_webhook(
        "🗑️ ホワイトリスト削除（ロール）",
        [
            ("サーバー", f"{interaction.guild.name} ({interaction.guild.id})", False),
            ("対象ロール", f"{role.name} ({role.id})", False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
        ],
        0xff4444
    )


@whitelist_group.command(
    name="view",
    description="ホワイトリストに登録されているメンバー・ロールを表示します"
)
async def white_list_view(interaction: discord.Interaction):
    # 権限チェック
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message("❌ このコマンドを実行するには**サーバー管理**権限が必要です。", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)

    guild = interaction.guild
    if guild is None:
        await interaction.followup.send("❌ サーバー内でのみ使用できます。", ephemeral=True)
        return

    cur.execute(
        "SELECT user_id FROM whitelist_users WHERE guild_id=?",
        (guild.id,)
    )
    user_rows = cur.fetchall()

    whitelisted_users = []
    for (user_id,) in user_rows:
        member = guild.get_member(user_id)
        if member:
            whitelisted_users.append(f"{member.mention} (`{member.id}`)")
        else:
            whitelisted_users.append(f"不明なユーザー (`{user_id}`)")

    cur.execute(
        "SELECT role_id FROM whitelist_roles WHERE guild_id=?",
        (guild.id,)
    )
    role_rows = cur.fetchall()

    whitelisted_roles = []
    for (role_id,) in role_rows:
        role = guild.get_role(role_id)
        if role:
            whitelisted_roles.append(f"{role.mention} (`{role.id}`)")
        else:
            whitelisted_roles.append(f"削除済みロール (`{role_id}`)")

    embed = discord.Embed(
        title="✅ ホワイトリスト一覧",
        description=f"サーバー: **{guild.name}**",
        color=discord.Color.green()
    )

    embed.add_field(
        name="👤 ホワイトリストユーザー",
        value="\n".join(whitelisted_users) if whitelisted_users else "登録されていません",
        inline=False
    )

    embed.add_field(
        name="🎭 ホワイトリストロール",
        value="\n".join(whitelisted_roles) if whitelisted_roles else "登録されていません",
        inline=False
    )

    embed.set_footer(text=f"Guild ID: {guild.id}")

    await interaction.followup.send(embed=embed, ephemeral=True)

bot.tree.add_command(whitelist_group)
# ===============================
# WARN (Non-Group)
# ===============================

@bot.tree.command(
    name="warn",
    description="ユーザーに警告を送信します（DMで送信）"
)
async def warn(
    interaction: discord.Interaction,
    user: discord.Member,
    reason: str
):
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message("❌ このコマンドを実行するには**サーバー管理**権限が必要です。", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)

    guild = interaction.guild
    executor = interaction.user

    if guild is None:
        await interaction.followup.send("❌ サーバー内でのみ使用できます。", ephemeral=True)
        return

    embed = discord.Embed(
        title="⚠️ 警告",
        description="サーバー運営より警告が送信されました。",
        color=discord.Color.orange()
    )
    embed.add_field(name="サーバー", value=guild.name, inline=False)
    embed.add_field(name="理由", value=reason, inline=False)
    embed.set_footer(text="この警告は自動システムによって送信されました")

    try:
        await user.send(embed=embed)
    except discord.Forbidden:
        pass
    except Exception:
        pass

    await send_security_log(
        guild,
        "⚠️ Warn実行",
        [
            ("対象ユーザー", f"{user} ({user.id})", False),
            ("実行者", f"{executor} ({executor.id})", False),
            ("理由", reason, False),
        ],
        discord.Color.orange()
    )

    await interaction.followup.send(
        f"⚠️ {user.mention} に警告を送信しました。",
        ephemeral=True
    )

    log_user_action(
        action="warn",
        guild_id=guild.id,
        executor_id=interaction.user.id,
        target_id=user.id,
        extra={"reason": reason}
    )


# ===============================
# BLACKLIST GROUP
# ===============================
blacklist_group = app_commands.Group(name="blacklist", description="ブラックリスト関連のコマンド")

@blacklist_group.command(
    name="add_bot",
    description="Botをブラックリストに追加します（ID指定）"
)
async def bot_blacklist_add(
    interaction: discord.Interaction,
    id: str
):
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message("❌ このコマンドを実行するには**サーバー管理**権限が必要です。", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)

    guild = interaction.guild
    if guild is None:
        await interaction.followup.send("❌ サーバー内でのみ使用できます。", ephemeral=True)
        return

    if not id.isdigit():
        await interaction.followup.send("❌ IDは数字で指定してください。", ephemeral=True)
        return

    target_id = int(id)
    user = bot.get_user(target_id)

    if user is not None and not user.bot:
        await interaction.followup.send(
            "⚠️ 指定されたIDは **ユーザーID** です。Bot IDを指定してください。",
            ephemeral=True
        )
        return

    cur.execute(
        "SELECT 1 FROM bot_blacklist WHERE bot_id=?",
        (target_id,)
    )
    if cur.fetchone():
        await interaction.followup.send(
            "ℹ️ そのBotは既にブラックリストに登録されています。",
            ephemeral=True
        )
        return

    cur.execute(
        "INSERT INTO bot_blacklist (bot_id) VALUES (?)",
        (target_id,)
    )
    conn.commit()

    kicked = False
    member = guild.get_member(target_id)
    if member and member.bot:
        try:
            await member.kick(reason="Botブラックリストに登録されたため")
            kicked = True
        except:
            pass

    await send_security_log(
        guild,
        "🚫 Bot ブラックリスト追加",
        [
            ("Bot ID", str(target_id), False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("即時Kick", "はい" if kicked else "未侵入 / 失敗", False),
        ],
        discord.Color.red()
    )

    await send_security_webhook(
        "🚫 Bot ブラックリスト追加",
        [
            ("サーバー", f"{guild.name} ({guild.id})", False),
            ("Bot ID", str(target_id), False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("即Kick", "はい" if kicked else "未侵入", False),
        ],
        0xff0000
    )

    await interaction.followup.send(
        f"✅ Bot (`{target_id}`) をブラックリストに追加しました。",
        ephemeral=True
    )

    log_user_action(
        action="bot_blacklist",
        guild_id=guild.id,
        executor_id=interaction.user.id,
        target_id=target_id,
        extra={"kicked": kicked}
    )

@blacklist_group.command(
    name="remove_bot",
    description="Botをブラックリストから解除します（ID指定）"
)
async def unblacklist(
    interaction: discord.Interaction,
    id: str
):
    # 権限チェック (統一されたエラーメッセージ形式)
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message(
            "❌ このコマンドを実行するには**サーバー管理**権限が必要です。",
            ephemeral=True
        )
        return

    # defer を実行
    await interaction.response.defer(ephemeral=True)

    guild = interaction.guild

    if guild is None:
        await interaction.followup.send(
            "❌ サーバー内でのみ使用できます。",
            ephemeral=True
        )
        return

    if not id.isdigit():
        await interaction.followup.send(
            "❌ IDは数字で指定してください。",
            ephemeral=True
        )
        return

    target_id = int(id)

    cur.execute(
        "SELECT 1 FROM bot_blacklist WHERE bot_id=?",
        (target_id,)
    )
    if not cur.fetchone():
        await interaction.followup.send(
            "❌ 指定されたBotはブラックリストに登録されていません。",
            ephemeral=True
        )
        return

    cur.execute(
        "DELETE FROM bot_blacklist WHERE bot_id=?",
        (target_id,)
    )
    conn.commit()

    user = bot.get_user(target_id)
    bot_name = (
        f"{user} ({user.id})"
        if user else f"Bot ID: {target_id}"
    )

    await send_security_log(
        guild,
        "✅ Bot ブラックリスト解除",
        [
            ("対象Bot", bot_name, False),
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("状態", "今後参加してもKickされません", False),
        ],
        discord.Color.green()
    )

    await interaction.followup.send(
        f"✅ Bot (`{target_id}`) をブラックリストから解除しました。",
        ephemeral=True
    )

    log_user_action(
        action="bot_unblacklist",
        guild_id=guild.id,
        executor_id=interaction.user.id,
        target_id=target_id
    )

@blacklist_group.command(
    name="add_image",
    description="指定した画像をブラックリストに追加します"
)
@app_commands.describe(image="ブラックリストに追加する画像")
async def add_blacklist_image(
    interaction: discord.Interaction,
    image: discord.Attachment
):
    # 管理者チェック (統一形式)
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message(
            "❌ このコマンドを実行するには**サーバー管理**権限が必要です。",
            ephemeral=True
        )
        return

    # defer を実行
    await interaction.response.defer(ephemeral=True)

    # 画像チェック
    if not image.content_type or not image.content_type.startswith("image/"):
        await interaction.followup.send(
            "❌ 画像ファイルを指定してください。",
            ephemeral=True
        )
        return

    # 容量制限チェック (500KB = 500 * 1024 bytes)
    if image.size > 500 * 1024:
        await interaction.followup.send(
            "❌ 画像サイズが大きすぎます。500KB以下の画像を指定してください。",
            ephemeral=True
        )
        return

    data = await image.read()
    image_hash = hash_image_bytes(data)

    # 既存チェック
    cur.execute(
        "SELECT 1 FROM image_blacklist WHERE image_hash=?",
        (image_hash,)
    )
    if cur.fetchone():
        await interaction.followup.send(
            "⚠️ この画像は既にブラックリストに登録されています。",
            ephemeral=True
        )
        return

    # 登録
    cur.execute(
        "INSERT INTO image_blacklist (image_hash) VALUES (?)",
        (image_hash,)
    )
    conn.commit()

    await interaction.followup.send(
        "✅ 画像をブラックリストに追加しました。",
        ephemeral=True
    )

    # audit log
    await send_security_log(
        interaction.guild,
        "🖼️ 画像ブラックリスト追加",
        [
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("SHA256", image_hash, False),
        ],
        discord.Color.red()
    )


@blacklist_group.command(
    name="remove_image",
    description="指定した画像をブラックリストから解除します"
)
@app_commands.describe(image="解除する画像")
async def unblacklist_image(
    interaction: discord.Interaction,
    image: discord.Attachment
):
    # 管理者チェック (統一形式)
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message(
            "❌ このコマンドを実行するには**サーバー管理**権限が必要です。",
            ephemeral=True
        )
        return

    # defer を実行
    await interaction.response.defer(ephemeral=True)

    # 画像チェック
    if not image.content_type or not image.content_type.startswith("image/"):
        await interaction.followup.send(
            "❌ 画像ファイルを指定してください。",
            ephemeral=True
        )
        return

    # 解除時も一応サイズチェック（登録時と同じ条件でハッシュを取るため）
    if image.size > 500 * 1024:
        await interaction.followup.send(
            "❌ 画像サイズが大きすぎます。500KB以下の画像を指定してください。",
            ephemeral=True
        )
        return

    data = await image.read()
    image_hash = hash_image_bytes(data)

    # 存在確認
    cur.execute(
        "SELECT 1 FROM image_blacklist WHERE image_hash=?",
        (image_hash,)
    )
    if not cur.fetchone():
        await interaction.followup.send(
            "❌ この画像はブラックリストに登録されていません。",
            ephemeral=True
        )
        return

    # 削除
    cur.execute(
        "DELETE FROM image_blacklist WHERE image_hash=?",
        (image_hash,)
    )
    conn.commit()

    await interaction.followup.send(
        "✅ 画像ブラックリストから解除しました。",
        ephemeral=True
    )

    # audit log
    await send_security_log(
        interaction.guild,
        "🖼️ 画像ブラックリスト解除",
        [
            ("実行者", f"{interaction.user} ({interaction.user.id})", False),
            ("SHA256", image_hash, False),
        ],
        discord.Color.green()
    )

# ツリーに追加
bot.tree.add_command(blacklist_group)


@bot.tree.command(
    name="user_info",
    description="指定したユーザーの情報を表示します"
)
async def user_info(
    interaction: discord.Interaction,
    user: discord.Member
):
    # 先に defer を実行
    await interaction.response.defer(ephemeral=True)

    guild = interaction.guild

    roles = [
        role.mention
        for role in user.roles
        if role != guild.default_role
    ]

    embed = discord.Embed(
        title="👤 ユーザー情報",
        color=discord.Color.blurple(),
        timestamp=discord.utils.utcnow()
    )

    embed.set_thumbnail(url=user.display_avatar.url)

    embed.add_field(
        name="ユーザー",
        value=f"{user} (`{user.id}`)",
        inline=False
    )

    embed.add_field(
        name="所持ロール",
        value=", ".join(roles) if roles else "なし",
        inline=False
    )

    embed.add_field(
        name="サーバー参加日",
        value=discord.utils.format_dt(user.joined_at, style="F")
        if user.joined_at else "不明",
        inline=False
    )

    embed.set_footer(text=f"Server: {guild.name}")

    # defer しているので followup を使用
    await interaction.followup.send(embed=embed, ephemeral=True)


# ===============================
# SERVER INFO
# ===============================
@bot.tree.command(
    name="server_info",
    description="サーバーの情報を表示します"
)
async def server_info(
    interaction: discord.Interaction
):
    await interaction.response.defer(ephemeral=True)

    guild = interaction.guild

    channel_count = (
        len(guild.text_channels)
        + len(guild.voice_channels)
        + len(guild.categories)
    )

    embed = discord.Embed(
        title="🏠 サーバー情報",
        color=discord.Color.green(),
        timestamp=discord.utils.utcnow()
    )

    if guild.icon:
        embed.set_thumbnail(url=guild.icon.url)

    embed.add_field(
        name="サーバー名",
        value=guild.name,
        inline=False
    )

    embed.add_field(
        name="メンバー数",
        value=str(guild.member_count),
        inline=True
    )

    embed.add_field(
        name="チャンネル数",
        value=str(channel_count),
        inline=True
    )

    embed.add_field(
        name="作成日時",
        value=discord.utils.format_dt(guild.created_at, style="F"),
        inline=False
    )

    embed.add_field(
        name="サーバーID",
        value=f"`{guild.id}`",
        inline=False
    )

    await interaction.followup.send(embed=embed, ephemeral=True)


# ===============================
# ANTISPAM
# ===============================
@bot.tree.command(
    name="antispam",
    description="AntiSpam（スパム対策）を設定します"
)
async def antispam(interaction: discord.Interaction):
    # 権限チェック (統一されたエラーメッセージ形式)
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message(
            "❌ このコマンドを実行するには**サーバー管理**権限が必要です。",
            ephemeral=True
        )
        return

    # 権限がある場合は defer を実行
    await interaction.response.defer(ephemeral=True)

    guild = interaction.guild

    embed = discord.Embed(
        title="🛡️ AntiSpam 設定",
        description=(
            "検知時の処理内容：\n\n"
            "・URL スパム検知\n"
            "・短縮 URL 検知\n"
            "・短時間メッセージ連投検知\n"
            "・疑似メッセージ連投検知\n"
            "・メンションスパム検知\n"
            "・**リアクションスパム検知** (同一パターン連投)\n\n"
            "⚠️ 検知時：**10分間タイムアウト**"
        ),
        color=discord.Color.blue()
    )

    await interaction.followup.send(
        embed=embed,
        view=AntiSpamView(guild.id),
        ephemeral=True
    )

    log_user_action(
        action="antispam_panel_open",
        guild_id=guild.id,
        executor_id=interaction.user.id
    )

@bot.tree.command(
    name="perm_guard",
    description="権限付与荒らしを防止します"
)
@app_commands.describe(role="隔離に使用する遠隔ロール")
async def perm_guard(
    interaction: discord.Interaction,
    role: discord.Role
):
    # 権限チェック (統一形式)
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message(
            "❌ このコマンドを実行するには**サーバー管理**権限が必要です。",
            ephemeral=True
        )
        return

    # defer を実行
    await interaction.response.defer(ephemeral=True)

    cur.execute(
        "INSERT OR REPLACE INTO perm_guard VALUES (?, ?, ?)",
        (interaction.guild.id, 0, role.id)
    )
    conn.commit()

    embed = discord.Embed(
        title="🛡️ Perm Guard 設定",
        description=f"隔離ロール: {role.mention}",
        color=discord.Color.dark_red()
    )

    # defer しているため followup を使用
    await interaction.followup.send(
        embed=embed,
        view=PermGuardView(interaction.guild.id),
        ephemeral=True
    )

    log_user_action(
        action="perm_guard_config",
        guild_id=interaction.guild.id,
        executor_id=interaction.user.id,
        target_id=None,
        extra={
            "isolation_role_id": role.id
        }
    )


@bot.tree.command(
    name="alert_mode",
    description="サーバーの警戒モードを設定します"
)
async def alert_mode(interaction: discord.Interaction):
    # 権限チェック (統一形式)
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message(
            "❌ このコマンドを実行するには**サーバー管理**権限が必要です。",
            ephemeral=True
        )
        return

    # defer を実行
    await interaction.response.defer(ephemeral=True)

    guild = interaction.guild
    if guild is None:
        await interaction.followup.send(
            "❌ サーバー内のみで使用できます。",
            ephemeral=True
        )
        return

    current = get_alert_mode(guild)

    embed = build_alert_mode_embed(current)

    await interaction.followup.send(
        embed=embed,
        view=AlertModeView(guild.id),
        ephemeral=True
    )

    log_user_action(
        action="alert_mode_open",
        guild_id=guild.id,
        executor_id=interaction.user.id,
        extra={
            "current_mode": current
        }
    )

@bot.tree.command(
    name="report",
    description="BOTの利用規約違反者を通報します"
)
@app_commands.describe(
    image="証拠画像（任意）"
)
async def report(
    interaction: discord.Interaction,
    image: discord.Attachment | None = None
):
    # ===============================
    # user_logs.json へ記録（最小）
    # ===============================
    log_user_action(
        guild_id=interaction.guild.id if interaction.guild else 0,
        action="report_opened",
        executor_id=interaction.user.id,
        extra={
            "has_image": image is not None
        }
    )
    await interaction.response.send_modal(
        ReportModal(image)
    )

@bot.tree.command(
    name="admin_warn",
    description="【BOT管理者専用】ユーザーに規約違反警告DMを送信",
    guild=discord.Object(id=MODERATION_SERVER_ID)
)
@app_commands.describe(
    id="警告するユーザーID",
    reason="警告理由"
)
async def admin_warn(
    interaction: discord.Interaction,
    id: str,
    reason: str
):
    if interaction.user.id not in ADMIN_USER_ID:
        await interaction.response.send_message(
            "❌このコマンドはBot運営者以外は実行できません",
            ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)

    if not id.isdigit():
        await interaction.followup.send("IDは数字で指定してください。", ephemeral=True)
        return

    user = await bot.fetch_user(int(id))

    embed = discord.Embed(
        title="⚠️ 規約違反警告",
        color=discord.Color.orange()
    )
    embed.description = (
        "あなたは **Securo Warden** から警告されました。\n\n"
        f"**警告理由**\n{reason}"
    )

    try:
        await user.send(embed=embed)
    except:
        pass

    await interaction.followup.send("✅ 警告DMを送信しました。", ephemeral=True)


# ===============================
# ADMIN PENALTY SET
# ===============================
@bot.tree.command(
    name="admin_penalty_set",
    description="【BOT管理者専用】ユーザーの利用を停止させます",
    guild=discord.Object(id=MODERATION_SERVER_ID)
)
@app_commands.describe(
    id="対象ユーザーID",
    reason="停止理由",
    duration="停止期間（例: 10m, 2h, 1d / 未入力で無期限）",
    proof="証拠となるスクリーンショット等（任意）",
    dm="Trueで利用停止DMを送信、Falseで送信しません"
)
async def admin_penalty_set(
    interaction: discord.Interaction,
    id: str,
    reason: str,
    duration: str | None = None,
    proof: discord.Attachment | None = None,
    dm: bool = True
):
    if interaction.user.id not in ADMIN_USER_ID:
        await interaction.response.send_message(
            "❌このコマンドはBot運営者以外実行できません",
            ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)

    if not id.isdigit():
        await interaction.followup.send("IDは数字で指定してください。", ephemeral=True)
        return

    seconds = parse_duration(duration) if duration else None
    until = int(time.time()) + seconds if seconds else None

    # DBへの保存（措置自体は画像なしでも実行）
    cur.execute(
        "INSERT OR REPLACE INTO admin_penalties VALUES (?, ?, ?)",
        (int(id), until, reason)
    )
    conn.commit()

    # DM送信の制御
    if dm:
        try:
            user = await bot.fetch_user(int(id))
            embed = discord.Embed(
                title="🚫 利用停止通知",
                color=discord.Color.red()
            )
            embed.description = (
                "あなたは **Securo Warden** の利用が停止されました。\n\n"
                f"**利用停止期間**\n{'無期限' if until is None else duration}\n\n"
                f"**理由**\n{reason}"
            )
            
            # 証拠画像がある場合はEmbedにセット
            if proof:
                # 画像のURLをEmbedのメイン画像として設定
                embed.set_image(url=proof.url)
                embed.set_footer(text="※添付された画像は、利用規約違反の証拠として記録されています。")

            await user.send(embed=embed)
        except Exception:
            # DM閉鎖などの場合はスキップ
            pass

    status_msg = f"✅ 利用停止を設定しました。({'DM送信済み' if dm else 'DM未送信'})"
    if proof:
        status_msg += "\n📸 証拠画像を添付しました。"
        
    await interaction.followup.send(status_msg, ephemeral=True)

# ===============================
# ADMIN PENALTY REMOVE
# ===============================
@bot.tree.command(
    name="admin_penalty_remove",
    description="【BOT管理者専用】利用停止解除",
    guild=discord.Object(id=MODERATION_SERVER_ID)
)
@app_commands.describe(
    id="対象ユーザーID",
    reason="解除理由"
)
async def admin_penalty_remove(
    interaction: discord.Interaction,
    id: str,
    reason: str
):
    if interaction.user.id not in ADMIN_USER_ID:
        await interaction.response.send_message(
            "❌このコマンドはBot運営者以外実行できません",
            ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)

    if not id.isdigit():
        await interaction.followup.send("IDは数字で指定してください。", ephemeral=True)
        return

    cur.execute(
        "DELETE FROM admin_penalties WHERE user_id=?",
        (int(id),)
    )
    conn.commit()

    user = await bot.fetch_user(int(id))

    embed = discord.Embed(
        title="✅ 利用停止解除",
        color=discord.Color.green()
    )
    embed.description = (
        "あなたの **Securo Warden 利用停止** が解除されました。\n\n"
        f"**解除理由**\n{reason}"
    )

    try:
        await user.send(embed=embed)
    except:
        pass

    await interaction.followup.send("✅ 利用停止を解除しました。", ephemeral=True)

@bot.tree.command(
    name="admin_sendmessage",
    description="【BOT運営者専用】指定したユーザーに埋め込みメッセージを送信します",
    guild=discord.Object(id=MODERATION_SERVER_ID)
)
@app_commands.describe(
    userid="送信先ユーザーのID",
    title="埋め込みのタイトル（15文字以内）",
    message="送信する内容（100文字以内）"
)
async def admin_sendmessage(
    interaction: discord.Interaction,
    userid: str,
    title: str,
    message: str
):
    # 1. 管理者チェック
    if interaction.user.id not in ADMIN_USER_ID:
        await interaction.response.send_message(
            "❌ このコマンドはBot運営者以外実行できません",
            ephemeral=True
        )
        return

    # 2. 応答の保留（defer）
    await interaction.response.defer(ephemeral=True)

    # 3. 文字数バリデーション
    if len(title) > 15:
        await interaction.followup.send(
            f"❌ タイトルが長すぎます（現在 {len(title)} 文字 / 最大 15 文字）",
            ephemeral=True
        )
        return

    if len(message) > 100:
        await interaction.followup.send(
            f"❌ 内容が長すぎます（現在 {len(message)} 文字 / 最大 100 文字）",
            ephemeral=True
        )
        return

    # 4. IDの形式チェック
    if not userid.isdigit():
        await interaction.followup.send("❌ ユーザーIDは数字で指定してください。", ephemeral=True)
        return

    try:
        # 5. ユーザーの取得と送信
        target_user = await bot.fetch_user(int(userid))
        
        embed = discord.Embed(
            title=title,
            description=message,
            color=discord.Color.blue() # 青色の埋め込み
        )
        # 管理者からのメッセージであることを明示（任意）
        embed.set_footer(text="Securo Warden 管理チームからの通知")

        await target_user.send(embed=embed)
        await interaction.followup.send(f"✅ <@{userid}> へのメッセージ送信が完了しました。", ephemeral=True)

    except discord.NotFound:
        await interaction.followup.send("❌ 指定されたユーザーが見つかりませんでした。", ephemeral=True)
    except discord.Forbidden:
        await interaction.followup.send("❌ ユーザーにDMを送信できません（DMが閉じられている可能性があります）。", ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f"❌ 予期しないエラーが発生しました: {e}", ephemeral=True)

# ===============================
# ADMIN THANKS DM
# ===============================
@bot.tree.command(
    name="admin_thanks_dm",
    description="【BOT管理者専用】通報感謝DM",
    guild=discord.Object(id=MODERATION_SERVER_ID)
)
@app_commands.describe(
    id="送信先ユーザーID",
    message="感謝メッセージ"
)
async def admin_thanks_dm(
    interaction: discord.Interaction,
    id: str,
    message: str
):
    if interaction.user.id not in ADMIN_USER_ID:
        await interaction.response.send_message(
            "❌このコマンドはBot運営者以外実行できません",
            ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)

    if not id.isdigit():
        await interaction.followup.send("IDは数字で指定してください。", ephemeral=True)
        return

    user = await bot.fetch_user(int(id))

    embed = discord.Embed(
        title="🙏 ご通報ありがとうございます",
        color=discord.Color.blurple()
    )
    embed.description = (
        "ご通報いただきありがとうございます。\n\n"
        f"{message}"
    )

    try:
        await user.send(embed=embed)
    except:
        pass

    await interaction.followup.send("✅ 感謝DMを送信しました。", ephemeral=True)

# ===============================
# 通報ログチャンネル設定
# ===============================
@bot.tree.command(name="reportlog_channel", description="サーバーメンバーからの通報ログを送信するチャンネルを設定します")
@app_commands.describe(channel="通報ログを受け取るチャンネル")
@app_commands.checks.has_permissions(manage_guild=True)
async def report_log_channel(interaction: discord.Interaction, channel: discord.TextChannel):

    # 管理者権限チェック
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message(
            "❌ このコマンドを実行するには**サーバー管理**権限が必要です。",
            ephemeral=True
        )
        return

    # deferを実行
    await interaction.response.defer(ephemeral=True)

    cur.execute(
        "REPLACE INTO report_log_channel (guild_id, channel_id) VALUES (?, ?)",
        (interaction.guild.id, channel.id)
    )
    conn.commit()

    await interaction.followup.send(
        f"✅ 通報ログチャンネルを {channel.mention} に設定しました。",
        ephemeral=True
    )

@bot.tree.command(
    name="help",
    description="Botのコマンド一覧を確認できます"
)
async def help_command(interaction: discord.Interaction):
    # deferを実行
    await interaction.response.defer(ephemeral=True)

    # 上部メッセージ用 Embed（通常の埋め込み）
    info_embed = discord.Embed(
        description="全てのコマンドはこちらのサイトから確認できます",
        color=discord.Color.blue()
    )

    # 下部リンク用 Embed（画像のような外部リンク表示）
    link_embed = discord.Embed(
        title="公式サイト",
        url="https://securowarden.com/commands",
        color=discord.Color.blue()
    )

    await interaction.followup.send(
        embeds=[info_embed, link_embed],
        ephemeral=True
    )

@bot.tree.command(
    name="admin_serverlist",
    description="【BOT管理者専用】Botが導入されているサーバー一覧をファイルで出力"
)
async def serverlist(interaction: discord.Interaction):
    # 🔒 管理者チェック（ADMIN_USER_ID セットを使用）
    if interaction.user.id not in ADMIN_USER_ID:
        # セキュリティのため、権限がない場合は「存在しない」と返す
        await interaction.response.send_message("❌このコマンドはBot運営者以外実行できません。", ephemeral=True)
        return

    # ✅ 処理（サーバー情報の収集）に時間がかかる可能性があるため defer
    await interaction.response.defer(ephemeral=True)

    # 🏠 サーバー情報の収集
    # 形式: - サーバー名 (ID: 0000) | オーナー: 名前 (ID: 0000)
    guild_info = []
    for guild in bot.guilds:
        # オーナー情報がキャッシュにない場合に備えて取得を試みる
        owner = guild.owner
        if not owner:
            try:
                owner = await guild.fetch_member(guild.owner_id)
                owner_info = f"{owner} ({owner.id})"
            except:
                owner_info = f"取得失敗 (Owner ID: {guild.owner_id})"
        else:
            owner_info = f"{owner} ({owner.id})"
            
        guild_info.append(f"- {guild.name} (ID: {guild.id}) | オーナー: {owner_info}")
    
    if not guild_info:
        await interaction.followup.send("Botはどのサーバーにも参加していません。", ephemeral=True)
        return

    # 📄 全体のテキストを作成
    header = f"📊 導入サーバー一覧（合計: {len(guild_info)} サーバー）\n"
    header += "="*50 + "\n"
    full_text = header + "\n".join(guild_info)

    # ✂️ 10,000文字制限の適用
    if len(full_text) > 10000:
        full_text = full_text[:10000] + "\n\n...(10,000文字制限により以下省略)"

    # 💾 メモリ上にテキストファイルを作成
    # io.BytesIO を使うことで、ディスクに保存せずに直接アップロード可能
    file_data = io.BytesIO(full_text.encode('utf-8'))
    discord_file = discord.File(fp=file_data, filename="server_list.txt")

    # 📤 ファイルとして送信
    await interaction.followup.send(
        content=f"📊 **導入サーバー一覧（合計: {len(guild_info)} サーバー）をファイルで出力しました。**",
        file=discord_file,
        ephemeral=True
    )

backup_group = app_commands.Group(name="backup", description="サーバーのバックアップ・復元に関連するコマンド")

@backup_group.command(
    name="key",
    description="サーバーのフルバックアップを作成します"
)
async def add_backup_key(interaction: discord.Interaction):
    guild = interaction.guild
    
    # 所有者チェック
    if guild is None or interaction.user.id != guild.owner_id:
        await interaction.response.send_message(
            "❌ このコマンドはサーバー所有者のみ実行できます。",
            ephemeral=True
        )
        return

    # ===== 既存バックアップ確認 =====
    cur.execute(
        "SELECT 1 FROM backups WHERE source_guild_id=? LIMIT 1",
        (guild.id,)
    )
    if cur.fetchone():
        await interaction.response.send_message(
            "❌ このサーバーには既にバックアップがあります。",
            ephemeral=True
        )
        return

    # defer を実行
    await interaction.response.defer(ephemeral=True)

    # ===== DM送信可能かテスト =====
    try:
        await interaction.user.send(
            f"🔐 バックアップキーを送信します。DMを閉じないでください。"
        )
    except discord.Forbidden:
        await interaction.followup.send(
            "❌ DMを送信できませんでした。\n"
            "ユーザー設定で『サーバーメンバーからのDMを許可』を有効にしてください。",
            ephemeral=True
        )
        return

    # ===== バックアップ作成 =====
    backup_data = await create_guild_backup(guild)
    key = generate_backup_key()

    cur.execute(
        "INSERT INTO backups VALUES (?, ?, ?, ?, ?)",
        (
            key,
            interaction.user.id,
            guild.id,
            int(time.time()),
            json.dumps(backup_data)
        )
    )
    conn.commit()

    # ===== 本キー送信 =====
    try:
        await interaction.user.send(
            f"🔐 **バックアップ作成完了**\n"
            f"サーバー: **{guild.name}**\n\n"
            f"バックアップキー:\n"
            f"**{key}**\n\n"
            f"大切に保管してください。"
        )
    except discord.Forbidden:
        await interaction.followup.send(
            "❌ バックアップ作成後にDM送信が失敗しました。",
            ephemeral=True
        )
        return

    await interaction.followup.send(
        "✅ バックアップを作成しました。キーをDMに送信しました。",
        ephemeral=True
    )


# ===============================
# BACKUP CONFIRM (旧 backup)
# ===============================
@backup_group.command(
    name="confirm",
    description="バックアップキーを使用して復元します"
)
@app_commands.describe(key="バックアップキー")
async def backup_confirm(interaction: discord.Interaction, key: str):
    if interaction.guild is None:
        return

    # defer を実行
    await interaction.response.defer(ephemeral=True)

    await interaction.followup.send(
        "⚠️ 本当にサーバーを復元しますか？\n"
        "現在のチャンネル・ロールは削除されます。",
        view=BackupConfirmView(interaction.user.id, key),
        ephemeral=True
    )

# ツリーに追加
bot.tree.add_command(backup_group)


@bot.tree.command(
    name="invite_safemode",
    description="招待リンク大量作成を防止します"
)
async def invite_safemode(interaction: discord.Interaction):
    # 権限チェック（形式統一）
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message(
            "❌ このコマンドを実行するには**サーバー管理**権限が必要です。",
            ephemeral=True
        )
        return

    # defer を実行
    await interaction.response.defer(ephemeral=True)

    guild = interaction.guild

    embed = discord.Embed(
        title="🔗 Invite SafeMode",
        description=(
            "以下を監視します：\n\n"
            "・短時間での招待リンク大量作成\n"
            "・荒らし・侵入準備行為\n\n"
            "⚠️ 検知時：\n"
            "・新規招待作成をブロック\n"
            "・監査ログへ通知"
        ),
        color=discord.Color.blurple()
    )

    await interaction.followup.send(
        embed=embed,
        view=InviteSafeModeView(guild.id),
        ephemeral=True
    )

    log_user_action(
        action="invite_safemode_panel_open",
        guild_id=guild.id,
        executor_id=interaction.user.id
    )


# ===============================
# SERVER WEAKPOINT
# ===============================
@bot.tree.command(
    name="server_weakpoint",
    description="サーバーの弱点を本格的に診断します"
)
@app_commands.describe(
    type="診断タイプ",
    ホワイトリスト除外="ホワイトリストロールを除外（権限を選択した場合のみ）"
)
@app_commands.choices(type=[
    app_commands.Choice(name="Bot", value="bot"),
    app_commands.Choice(name="User", value="user"),
    app_commands.Choice(name="権限", value="perm"),
    app_commands.Choice(name="ロール構成", value="role")
])
async def server_weakpoint(
    interaction: discord.Interaction,
    type: app_commands.Choice[str],
    ホワイトリスト除外: bool = False
):
    guild = interaction.guild

    if guild is None:
        await interaction.response.send_message(
            "❌ サーバー内で実行してください。",
            ephemeral=True
        )
        return

    # 🔐 権限チェック（形式統一）
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message(
            "❌ このコマンドを実行するには**サーバー管理**権限が必要です。",
            ephemeral=True
        )
        return

    # ❌ 権限以外でホワイトリスト除外使用禁止
    if type.value != "perm" and ホワイトリスト除外:
        await interaction.response.send_message(
            "❌ 『ホワイトリスト除外』は「権限」診断でのみ使用できます。",
            ephemeral=True
        )
        return

    # defer を実行
    await interaction.response.defer(ephemeral=True)

    result = ""

    try:
        # BOT 診断
        if type.value == "bot":
            for m in guild.members:
                if not m.bot:
                    continue
                days = inactive_days(m)
                if days >= 60:
                    danger = "🔴 非常に高"
                elif days >= 30:
                    danger = "🔴 高"
                elif days >= 14:
                    danger = "🟠 中"
                else:
                    continue
                result += (
                    f"🤖 {m}\n"
                    f"非活動: {days}日\n"
                    f"危険度: {danger}\n"
                    f"理由: 長期間活動していないBotは乗っ取りや悪用の可能性\n"
                    f"対策: 不要ならKick、権限削除、開発元確認を推奨\n\n"
                )
            if not result:
                result = "✅ 危険なBotは見つかりませんでした."

        # USER 診断
        elif type.value == "user":
            for m in guild.members:
                if m.bot:
                    continue
                if looks_random(m.name):
                    result += (
                        f"👤 {m}\n"
                        f"危険度: 🔴 非常に高\n"
                        f"理由: スパムで多いランダム名\n"
                        f"対策: 認証導入・新規制限・監視\n\n"
                    )
                elif is_default_avatar(m):
                    result += (
                        f"👤 {m}\n"
                        f"危険度: 🟠 中\n"
                        f"理由: 初期アイコンは捨てアカウント荒らしの可能性\n"
                        f"対策: 新規参加制限や認証機能を導入\n\n"
                    )
            if not result:
                result = "✅ 危険なユーザーは見つかりませんでした."

        # 権限 診断
        elif type.value == "perm":
            whitelist = set()
            if ホワイトリスト除外:
                try:
                    cur.execute(
                        "SELECT role_id FROM whitelist_roles WHERE guild_id=?",
                        (guild.id,)
                    )
                    whitelist = {row[0] for row in cur.fetchall()}
                except Exception as e:
                    result += f"⚠️ ホワイトリスト取得エラー: {e}\n\n"

            for role in guild.roles:
                if role in guild.me.roles:
                    continue
                if role.id in whitelist:
                    continue
                perms = role.permissions
                for p, reason in DANGEROUS_PERMS.items():
                    if getattr(perms, p, False):
                        result += (
                            f"🛡️ {role.name}\n"
                            f"危険権限: {p}\n"
                            f"理由: {reason}\n"
                            f"危険度: 🔴 非常に高\n"
                            f"対策: 信頼できる役職のみに付与\n\n"
                        )
            if not result:
                result = "✅ 危険な権限は見つかりませんでした."

        # ロール構成 診断
        elif type.value == "role":
            for m in guild.members:
                if not m.bot:
                    continue
                if m.top_role.position < guild.me.top_role.position - 5:
                    result += (
                        f"🤖 {m}\n"
                        f"危険度: 🟠 中\n"
                        f"理由: Botロールが低く管理不能になる可能性\n"
                        f"対策: Botロールを通常メンバーより上位へ移動\n\n"
                    )
            if not result:
                result = "✅ 問題のあるロール構成は見つかりませんでした."

    except Exception as e:
        result = f"❌ 診断中にエラーが発生しました:\n{e}"

    # 安全送信
    chunks = [result[i:i+4000] for i in range(0, len(result), 4000)]
    for chunk in chunks:
        embed = discord.Embed(
            title=f"🛡️ サーバー弱点診断 — {type.name}",
            description=chunk,
            color=discord.Color.red()
        )
        await interaction.followup.send(embed=embed, ephemeral=True)


# ===============================
# SLOW MODE
# ===============================
@bot.tree.command(
    name="slow_mode",
    description="チャンネルの低速モードを設定します"
)
@app_commands.describe(
    channel="対象チャンネル",
    time="例: 1s / 5m / 2h / 1d / 0s(解除)"
)
async def slow_mode(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
    time: str
):
    # 権限チェック（形式統一）
    if not interaction.user.guild_permissions.manage_channels:
        await interaction.response.send_message(
            "❌ このコマンドを実行するには**チャンネル管理**権限が必要です。",
            ephemeral=True
        )
        return

    if not interaction.guild.me.guild_permissions.manage_channels:
        await interaction.response.send_message(
            "❌ Botにチャンネル管理権限がありません。",
            ephemeral=True
        )
        return

    # defer を実行
    await interaction.response.defer(ephemeral=True)

    # チャンネルタイプ検証
    if not isinstance(channel, discord.TextChannel):
        await interaction.followup.send(
            "❌ テキストチャンネルのみ設定できます。",
            ephemeral=True
        )
        return

    seconds = parse_duration(time)

    if seconds is None:
        await interaction.followup.send(
            "❌ 時間の形式が正しくありません。\n例: 10s / 5m / 2h / 1d",
            ephemeral=True
        )
        return

    MAX_SLOWMODE = 21600  # 6時間

    if seconds > MAX_SLOWMODE:
        await interaction.followup.send(
            "❌ 低速モードは最大6時間まで設定可能です。",
            ephemeral=True
        )
        return

    try:
        await channel.edit(slowmode_delay=seconds)

        if seconds == 0:
            msg = f"✅ {channel.mention} の低速モードを解除しました。"
        else:
            msg = f"✅ {channel.mention} の低速モードを {seconds} 秒に設定しました。"

        await interaction.followup.send(msg)

    except discord.Forbidden:
        await interaction.followup.send(
            "❌ 権限不足で設定できません。",
            ephemeral=True
        )
    except discord.HTTPException:
        await interaction.followup.send(
            "❌ Discord APIエラーが発生しました。",
            ephemeral=True
        )
    except Exception as e:
        await interaction.followup.send(
            "❌ 不明なエラーが発生しました。",
            ephemeral=True
        )

@bot.tree.command(name="verify_setup", description="メンバー認証パネルを設置します")
@app_commands.describe(
    type="認証方式を選択",
    role="付与するロールを選択",
    title="埋め込みのタイトル(最大20文字)",
    description="埋め込みの説明文(最大60文字)"
)
@app_commands.choices(type=[
    app_commands.Choice(name="計算", value="計算"),
    app_commands.Choice(name="サーバー名選択", value="サーバー名選択"),
    app_commands.Choice(name="ワンクリック認証", value="ワンクリック認証"),
    app_commands.Choice(name="ランダムコード", value="ランダムコード"),
])
async def verify_setup(
    interaction: discord.Interaction,
    type: str,
    role: discord.Role,
    title: str,
    description: str
):
    # 【追加】実行した瞬間にdeferし、応答までの猶予時間を確保
    await interaction.response.defer(ephemeral=True)

    # ユーザーの権限チェック
    if not interaction.user.guild_permissions.manage_guild:
        return await interaction.followup.send("❌コマンドを実行するには**サーバー管理**権限が必要です。", ephemeral=True)

    # 付与ロールのバリデーション
    if role.is_default() or role.is_bot_managed():
        return await interaction.followup.send("❌付与ロールに@everyoneやBotロールは選択できません。", ephemeral=True)

    # 文字数制限バリデーション
    if len(title) > 20:
        return await interaction.followup.send("❌タイトルは20文字以内で入力してください。", ephemeral=True)
    if len(description) > 60:
        return await interaction.followup.send("❌説明文は60文字以内で入力してください。", ephemeral=True)

    # Bot自体の権限チェック（ロール管理）
    if not interaction.guild.me.guild_permissions.manage_roles:
        return await interaction.followup.send("❌Botに必要な権限**ロール管理**が不足しています", ephemeral=True)

    # ロール順位チェック
    if interaction.guild.me.top_role <= role:
        return await interaction.followup.send("❌Botのロール位置が付与しようとしているロールよりも低いです。", ephemeral=True)

    try:
        # ===============================
        # DB保存処理（INSERT OR REPLACE）
        # ===============================
        cur.execute(
            "INSERT OR REPLACE INTO auth_settings (guild_id, auth_type, role_id) VALUES (?, ?, ?)",
            (interaction.guild_id, type, role.id)
        )
        conn.commit()

        embed = discord.Embed(
            title=title,
            description=description,
            color=discord.Color.green()
        )
        
        view = PersistentView(type, role.id)
        # メッセージはチャンネルへ送信
        await interaction.channel.send(embed=embed, view=view)
        # 結果通知はfollowupで送信
        await interaction.followup.send("✅認証パネルを設置し、設定を保存しました。", ephemeral=True)

    except Exception as e:
        error_name = type(e).__name__
        await interaction.followup.send(f"❌不明なエラー{error_name}が発生しました。", ephemeral=True)
        traceback.print_exc()

@bot.tree.command(name="admin_update_terms", description="（Bot運営者専用）利用規約を更新します")
async def admin_update_terms(interaction: discord.Interaction):
    if interaction.user.id not in ADMIN_USER_ID:
        await interaction.response.send_message(
            "❌ このコマンドはBot運営者以外は実行できません。",
            ephemeral=True
        )
        return

    # deferを実行
    await interaction.response.defer(ephemeral=True)

    try:
        cur.execute("SELECT version FROM terms_current LIMIT 1")
        version = cur.fetchone()[0]

        new_version = version + 1

        cur.execute("DELETE FROM terms_current")
        cur.execute("INSERT INTO terms_current VALUES (?)", (new_version,))

        conn.commit()

        await interaction.followup.send(
            f"✅ 利用規約を更新しました\n新バージョン: **{new_version}**",
            ephemeral=True
        )

    except Exception:
        try:
            await interaction.followup.send(
                "❌ エラーが発生しました。",
                ephemeral=True
            )
        except:
            pass


# ===============================
# ADMIN SERVER LEAVE
# ===============================
@bot.tree.command(name="admin_server_leave", description="（Bot運営者専用）サーバーをブラックリスト登録し退出")
async def leave(interaction: discord.Interaction, id: str, duration: typing.Optional[str] = None):
    if interaction.user.id not in ADMIN_USER_ID:
        await interaction.response.send_message(
            "❌ このコマンドはBot運営者以外は実行できません。",
            ephemeral=True
        )
        return

    # deferを実行
    await interaction.response.defer(ephemeral=True)

    try:
        g_id = int(id)
        expiry = None
        
        if duration:
            seconds = parse_duration(duration)
            if seconds is None:
                return await interaction.followup.send("❌期間形式(1s,1m,1h,1d)が不正です。", ephemeral=True)
            
            expiry = datetime.now(timezone.utc) + timedelta(seconds=seconds)
        
        save_bl(g_id, expiry)
        
        guild = bot.get_guild(g_id)
        status = f"🚫 ID:`{g_id}` を{'永久' if not duration else duration}停止に設定しました。"
        
        if guild:
            await guild.leave()
            status += f"\n✅ サーバー「{guild.name}」から退出しました。"
        else:
            status += "\nℹ️ 現在参加していないサーバーですが、ブラックリストに登録しました。"
            
        await interaction.followup.send(status, ephemeral=True)
        
    except ValueError:
        await interaction.followup.send("❌有効なサーバーID（数字）を入力してください。", ephemeral=True)
    except Exception as e:
        print(f"[ERROR][admin_server_leave] {repr(e)}")
        await interaction.followup.send(f"🔥予期せぬエラーが発生しました。", ephemeral=True)


# ===============================
# FOLLOW ANNOUNCEMENTS
# ===============================
@bot.tree.command(
    name="follow_announcements",
    description="Botサポート鯖のお知らせ / 変更ログを受信するチャンネルを設定します"
)
@app_commands.describe(
    channel="お知らせを受け取りたいチャンネル",
    type="受信する内容の種類"
)
@app_commands.choices(
    type=[
        app_commands.Choice(name="お知らせ", value="お知らせ"),
        app_commands.Choice(name="変更ログ", value="変更ログ"),
    ]
)
async def announce(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
    type: app_commands.Choice[str],
):
    guild = interaction.guild
    member = interaction.user

    if not member.guild_permissions.manage_guild:
        await interaction.response.send_message(
            "❌ このコマンドを実行するには**サーバー管理**権限が必要です。",
            ephemeral=True
        )
        return

    # deferを実行
    await interaction.response.defer(ephemeral=True)

    bot_member = guild.me
    perms = channel.permissions_for(bot_member)

    if not perms.view_channel or not perms.send_messages:
        await interaction.followup.send(
            f"❌ {channel.mention} に対する Bot の権限が不足しています。",
            ephemeral=True
        )
        return

    if not perms.manage_webhooks:
        await interaction.followup.send(
            f"❌ {channel.mention} に対する **Webhook管理権限** が必要です。",
            ephemeral=True
        )
        return

    support_channel_id = SUPPORT_NEWS_CHANNEL_IDS.get(type.value)
    support_channel = interaction.client.get_channel(support_channel_id)

    if not isinstance(support_channel, discord.TextChannel):
        await interaction.followup.send(
            "❌ サポート鯖のニュースチャンネルが見つかりません。",
            ephemeral=True
        )
        return

    if not support_channel.is_news():
        await interaction.followup.send(
            "❌ 指定されたサポートチャンネルタイプはニュースチャンネルではありません。",
            ephemeral=True
        )
        return

    try:
        await support_channel.follow(destination=channel)
    except discord.Forbidden:
        await interaction.followup.send(
            "❌ チャンネルフォロー権限がありません。",
            ephemeral=True
        )
        return
    except discord.HTTPException:
        await interaction.followup.send(
            "❌ Discord API エラーが発生しました。",
            ephemeral=True
        )
        return

    cur.execute(
        """
        INSERT INTO announce_channels (guild_id, channel_id, type)
        VALUES (?, ?, ?)
        ON CONFLICT(guild_id, type)
        DO UPDATE SET channel_id=excluded.channel_id
        """,
        (guild.id, channel.id, type.value)
    )
    conn.commit()

    await interaction.followup.send(
        f"✅ **{type.value}** を {channel.mention} で受信する設定が完了しました。",
        ephemeral=True
    )


# ===============================
# ADMIN GLOBAL ANNOUNCEMENT
# ===============================
@bot.tree.command(
    name="admin_global_announcement", 
    description="（Bot運営者専用）全サーバーの所有者のDMにメッセージを送信します"
)
@app_commands.describe(title="埋め込みタイトル", message="送信メッセージ入力")
async def admin_global_announcement(interaction: discord.Interaction, title: str, message: str):
    if interaction.user.id not in ADMIN_USER_ID:
        await interaction.response.send_message(
            "❌ このコマンドはBot運営者以外は実行できません。", 
            ephemeral=True
        )
        return

    # deferを実行
    await interaction.response.defer(ephemeral=True)

    confirm_embed = discord.Embed(
        title="⚠️ 実行確認：一斉アナウンス",
        description=(
            "本当に全導入サーバーのオーナーのDMへ送信しますか？\n"
            "もし間違えて実行してしまった場合はただちにキャンセルをクリックしてください。\n"
            "また、Bot管理者の許可なく送信することを固く禁じます。"
        ),
        color=discord.Color.orange()
    )
    confirm_embed.add_field(name="プレビュー：タイトル", value=title, inline=False)
    confirm_embed.add_field(name="プレビュー：内容", value=message, inline=False)

    view = ConfirmView(title, message, interaction.user.id)
    
    await interaction.followup.send(
        embed=confirm_embed, 
        view=view, 
        ephemeral=True
    )

@bot.tree.command(
    name="antiphishing", 
    description="詐欺、危険リンク対策を設定します"
)
async def antiphishing(interaction: discord.Interaction):
    # 最初にレスポンスを保留（ephemeral設定を維持）
    await interaction.response.defer(ephemeral=True)

    # 権限チェック
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.followup.send(
            "❌ このコマンドを実行するには**サーバー管理**権限が必要です。", 
            ephemeral=True
        )
        return

    guild_id = interaction.guild_id

    # Embed の作成
    embed = discord.Embed(
        title="🛡️ Anti-Phishing 設定",
        description=(
            "検知時の処理内容：\n\n"
            "・**タイポスクワッティング検知** (discordd.com等)\n"
            "・**Unicode偽装ドメイン検知**\n"
            "・**短縮URL自動展開スキャン**\n"
            "・**不適切な招待URL検知** (Free Nitro等)\n"
            "・**不適切・成人向け単語検知**\n"
            "・**アカウント作成勧誘・名義貸し詐欺文脈検知**\n"
            "・**ドメイン形式ミス検知** (wwwdiscord.com等)\n\n"
            "⚠️ 検知時：**メッセージ削除 ＋ 10分間タイムアウト**"
        ),
        color=discord.Color.blue()
    )

    # defer しているので followup.send を使用
    await interaction.followup.send(
        embed=embed, 
        view=AntiPhishingView(guild_id), 
        ephemeral=True
    )

    # ログ記録
    log_user_action(
        action="antiphishing_panel_open",
        guild_id=guild_id,
        executor_id=interaction.user.id
    )

@bot.tree.command(name="embed_create", description="【サポート参加特典】カスタムEmbedを作成します")
async def embed_create(interaction: discord.Interaction):
    # --- 1. サポートサーバー参加チェック ---
    support_guild = bot.get_guild(SUPPORT_GUILD_ID)
    
    # ユーザーがサポートサーバーに在籍しているか確認
    is_member = False
    if support_guild:
        member = support_guild.get_member(interaction.user.id)
        if member:
            is_member = True
    else:
        # Botがサポート鯖にいない、またはキャッシュがない場合の再取得試行
        try:
            member = await support_guild.fetch_member(interaction.user.id)
            if member:
                is_member = True
        except:
            pass

    if not is_member:
        await interaction.response.send_message(
            f"❌ このコマンドは **SecuroWarden サポートサーバー** の参加者限定コマンドです。\n"
            f"以下より参加して、もう一度実行してください。\n"
            f"🔗 {SUPPORT_LINK}",
            ephemeral=True
        )
        return

    # --- 2. 権限チェック ---
    # 管理者以外が乱用できないよう「メッセージ管理権限」を必須にする
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message(
            "❌ このコマンドを実行するには**メッセージ管理**権限が必要です。", 
            ephemeral=True
        )
        return

    # --- 3. フォーム（Modal）を表示 ---
    await interaction.response.send_modal(EmbedCreateModal())

@bot.tree.command(name="securitylog_channel", description="サーバーに対する脅威を通知するチャンネルを設定します")
@app_commands.describe(channel="通知を送信するチャンネル")
async def securitylog_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    # 権限チェック (形式統一)
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message(
            "❌ このコマンドを実行するには**サーバー管理**権限が必要です。", 
            ephemeral=True
        )
        return

    # すでに defer があるためそのまま利用
    await interaction.response.defer(ephemeral=True)
    
    webhook_name = "Securo Warden Security Logs"
    icon_path = "/home/developer/bot2/securoicon.png"
    target_webhook = None

    try:
        # 既存のWebhookを探す
        webhooks = await channel.webhooks()
        for wh in webhooks:
            if wh.name == webhook_name:
                target_webhook = wh
                break
        
        # なければ作成
        if not target_webhook:
            avatar_data = None
            # os.path.exists を使用。osモジュールがインポートされている前提
            if os.path.exists(icon_path):
                with open(icon_path, "rb") as f:
                    avatar_data = f.read()
            
            target_webhook = await channel.create_webhook(
                name=webhook_name, 
                avatar=avatar_data, 
                reason="Securo Warden Security Log Setup"
            )

        # データベースを更新 (外部で定義された conn, cur を使用)
        cur.execute("""
            INSERT OR REPLACE INTO security_settings (guild_id, channel_id, webhook_url)
            VALUES (?, ?, ?)
        """, (interaction.guild.id, channel.id, target_webhook.url))
        conn.commit()

        await interaction.followup.send(
            f"✅ セキュリティ通知チャンネルを {channel.mention} に設定しました。",
            ephemeral=True
        )
    except discord.Forbidden:
        await interaction.followup.send(
            "❌ 権限不足です。Botに『ウェブフックの管理』権限が付与されているか確認してください。",
            ephemeral=True
        )
    except Exception as e:
        # デバッグが必要な場合は print(e) を追加
        await interaction.followup.send(
            "❌ 設定中に予期せぬエラーが発生しました。",
            ephemeral=True
        )

@bot.tree.command(name="antiraid", description="Raidによる大規模攻撃防止を設定します")
async def antiraid(interaction: discord.Interaction):
    # 権限チェック
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message("❌ このコマンドを実行するには**サーバー管理**権限が必要です。", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)

    embed = discord.Embed(
        title="🛡️ Anti-Raid 設定",
        description=(
            "サーバーへの一斉侵入や大規模荒らしを自動防衛します。\n\n"
            "**防衛プロトコル：**\n"
            "・**連続参加検知**: 10秒間に5人以上の参加で即座に招待リンクを無効化\n"
            "・**緊急ロックダウン**: 異常検知時、全チャンネルの `@everyone` 送信権限を即座に剥奪\n"
            "・**高速一括パージ**: 検知された攻撃アカウントを並列処理で最速BAN\n\n"
            "⚠️ 有効化すると、検知時に管理ログへ赤色緊急通知が送信されます。"
        ),
        color=discord.Color.blue()
    )
    
    await interaction.followup.send(embed=embed, view=AntiRaidView(), ephemeral=True)

@bot.tree.command(name="antinuke", description="サーバーの破壊行為（Nuke）を強力に防止します")
async def antinuke(interaction: discord.Interaction):
    # --- 権限チェック ---
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message(
            "❌このコマンドを実行するには**サーバー管理**権限が必要です。", 
            ephemeral=True
        )
        return

    # 1. 処理を開始する旨を伝える（ephemeral=True で自分にだけ見える）
    await interaction.response.defer(ephemeral=True)

    # 2. Embed の作成（Anti-Raid の例に合わせたスタイル）
    embed = discord.Embed(
        title="🛡️ Anti-Nuke 設定",
        description=(
            "サーバー管理権限の悪用や、Botによる大規模破壊を防止します。\n\n"
            "**防衛プロトコル：**\n"
            "・**権限乱用検知**: チャンネルの一斉削除やロールの大量変更を即座に遮断\n"
            "・**Bot招待者追放**: 許可なく導入された不正Botと、その**招待者を即座にBAN**\n"
            "・**即時復元支援**: 削除された重要な設定やチャンネルを保護・ログ記録\n\n"
            "⚠️ 有効化すると、異常検知時に攻撃者（管理者であっても）を即座に隔離します。"
        ),
        color=discord.Color.red()  # Nuke対策は緊急性が高いため赤色
    )

    # 3. Viewを設置して送信
    # 既に定義済みの AntiNukeView を使用
    await interaction.followup.send(
        embed=embed, 
        view=AntiNukeView(interaction.guild_id), 
        ephemeral=True
    )

@bot.tree.command(name="security_status", description="現在の各セキュリティ機能の有効状況を確認します")
async def security_status(interaction: discord.Interaction):
    # 1. 関数内で直接権限をチェック
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message("❌このコマンドを実行するには**サーバー管理**権限が必要です。", ephemeral=True)
        return

    # 2. 権限がある場合のみ defer を実行
    await interaction.response.defer(ephemeral=True)
    
    guild_id = interaction.guild_id

    try:
        # --- 各種設定の取得 ---
        
        # AntiNuke ( triggered を状態として判定 )
        cur.execute("SELECT triggered FROM antinuke_state WHERE guild_id=?", (guild_id,))
        row_nuke = cur.fetchone()
        antinuke = "ON" if row_nuke and row_nuke[0] == 1 else "OFF"

        # AntiSpam
        cur.execute("SELECT enabled FROM antispam_state WHERE guild_id=?", (guild_id,))
        row_spam = cur.fetchone()
        antispam = "ON" if row_spam and row_spam[0] == 1 else "OFF"

        # 権限荒らし防止 (perm_guard)
        cur.execute("SELECT enabled FROM perm_guard WHERE guild_id=?", (guild_id,))
        row_perm = cur.fetchone()
        perm_guard = "ON" if row_perm and row_perm[0] == 1 else "OFF"

        # 警戒モード (alert_mode)
        cur.execute("SELECT level FROM alert_mode WHERE guild_id=?", (guild_id,))
        row_alert = cur.fetchone()
        alert_mode = row_alert[0].capitalize() if row_alert else "Low"

        # 大量招待作成防止 (invite_safemode)
        cur.execute("SELECT enabled FROM invite_safemode WHERE guild_id=?", (guild_id,))
        row_invite = cur.fetchone()
        invite_safe = "ON" if row_invite and row_invite[0] == 1 else "OFF"

        # 詐欺対策 (antiphishing)
        cur.execute("SELECT enabled FROM antiphishing_state WHERE guild_id=?", (guild_id,))
        row_phishing = cur.fetchone()
        antiphishing = "ON" if row_phishing and row_phishing[0] == 1 else "OFF"

        # AntiRaid (antiraid_settings)
        cur.execute("SELECT enabled FROM antiraid_settings WHERE guild_id=?", (guild_id,))
        row_raid = cur.fetchone()
        antiraid = "ON" if row_raid and row_raid[0] == 1 else "OFF"

        # --- 埋め込みメッセージの構築 ---
        embed = discord.Embed(
            title="現在のサーバーステータス",
            color=discord.Color.red(),
            timestamp=discord.utils.utcnow()
        )
        
        status_text = (
            f"**Antinuke:** {antinuke}\n"
            f"**Antispam:** {antispam}\n"
            f"**権限荒らし防止:** {perm_guard}\n"
            f"**警戒モード:** {alert_mode}\n"
            f"**大量招待作成防止:** {invite_safe}\n"
            f"**詐欺対策:** {antiphishing}\n"
            f"**AntiRaid:** {antiraid}"
        )
        
        embed.description = status_text
        embed.set_footer(text=f"Server ID: {guild_id}")

        # 結果を送信
        await interaction.followup.send(embed=embed)

    except Exception as e:
        # 万が一のエラーハンドリング
        print(f"Error fetching security status: {e}")
        # defer後のためfollowupを使用
        await interaction.followup.send("❌ステータスの取得中にエラーが発生しました。", ephemeral=True)

lock_group = app_commands.Group(name="lock", description="指定チャンネルのロックコマンド")

# --- /lock add コマンド ---
@lock_group.command(name="add", description="指定したチャンネルをロックダウンします")
@app_commands.describe(channel="ロックするチャンネル選択")
async def lock_add(interaction: discord.Interaction, channel: discord.TextChannel):
    # 🌟 [条件チェック1] 実行したユーザーの権限確認
    if not interaction.user.guild_permissions.manage_channels:
        await interaction.response.send_message(
            "❌このコマンドを実行するには**チャンネルを管理**権限が必要です。",
            ephemeral=True
        )
        return

    # 🌟 [条件チェック2] Bot自身の権限確認
    bot_member = interaction.guild.me
    if not bot_member.guild_permissions.manage_channels:
        await interaction.response.send_message(
            "❌権限不足です。Botのロール権限に**チャンネルの管理**を付与してください",
            ephemeral=True
        )
        return

    # everyoneのロールオブジェクトと現在の権限（Overwrite）を取得
    everyone_role = interaction.guild.default_role
    current_overwrites = channel.overwrites_for(everyone_role)

    # 🌟 [条件チェック3] すでに指定の2つの権限が拒否（False）になっているか確認
    if current_overwrites.send_messages is False and current_overwrites.send_messages_in_threads is False:
        await interaction.response.send_message(
            "❌指定したチャンネルはすでにロックされています。",
            ephemeral=True
        )
        return

    # 🚀 権限の上書き設定（送信とスレッド送信を「拒否」に設定）
    current_overwrites.send_messages = False
    current_overwrites.send_messages_in_threads = False

    try:
        # チャンネルの権限を更新
        await channel.set_permissions(everyone_role, overwrite=current_overwrites)
        # 🌟 正常終了の応答（指定チャンネルをメンション表示）
        await interaction.response.send_message(
            f"✅{channel.mention}をロックダウンしました。",
            ephemeral=True
        )
    except Exception:
        # 万が一のDiscord APIエラー時のセーフティ
        await interaction.response.send_message(
            "❌チャンネルの権限更新中にエラーが発生しました。",
            ephemeral=True
        )


# --- /lock remove コマンド ---
@lock_group.command(name="remove", description="指定したチャンネルのロックダウンを解除します")
@app_commands.describe(channel="アンロックするチャンネル選択")
async def lock_remove(interaction: discord.Interaction, channel: discord.TextChannel):
    # 🌟 [条件チェック1] 実行したユーザーの権限確認
    if not interaction.user.guild_permissions.manage_channels:
        await interaction.response.send_message(
            "❌このコマンドを実行するには**チャンネルを管理**権限が必要です。",
            ephemeral=True
        )
        return

    # 🌟 [条件チェック2] Bot自身の権限確認
    bot_member = interaction.guild.me
    if not bot_member.guild_permissions.manage_channels:
        await interaction.response.send_message(
            "❌権限不足です。Botのロール権限に**チャンネルの管理**を付与してください",
            ephemeral=True
        )
        return

    everyone_role = interaction.guild.default_role
    current_overwrites = channel.overwrites_for(everyone_role)

    # 🌟 [条件チェック3] すでにロックが解除されている（拒否になっていない、つまり None または True）か確認
    if current_overwrites.send_messages is not False and current_overwrites.send_messages_in_threads is not False:
        await interaction.response.send_message(
            "❌指定したチャンネルはロックされていません。",
            ephemeral=True
        )
        return

    # 🚀 権限の解除設定（「拒否」を解除してデフォルトの「未設定(None)」に戻す）
    current_overwrites.send_messages = None
    current_overwrites.send_messages_in_threads = None

    try:
        await channel.set_permissions(everyone_role, overwrite=current_overwrites)
        await interaction.response.send_message(
            f"✅{channel.mention}のロックダウンを解除しました。",
            ephemeral=True
        )
    except Exception:
        await interaction.response.send_message(
            "❌チャンネルの権限更新中にエラーが発生しました。",
            ephemeral=True
        )

bot.tree.add_command(lock_group)

import asyncio
import discord
from discord import app_commands
from discord.ext import commands

# ※ botオブジェクトは既存のコードのものを使用してください
# bot = commands.Bot(...)

@bot.tree.command(
    name="disable_externalapps",
    description="指定したタイプの外部アプリ使用権限を一斉にOFFにします。"
)
@app_commands.choices(type=[
    app_commands.Choice(name="チャンネル", value="チャンネル"),
    app_commands.Choice(name="カテゴリ", value="カテゴリ"),
    app_commands.Choice(name="ロール", value="ロール")
])
async def disable_externalapps(
    interaction: discord.Interaction, 
    type: app_commands.Choice[str]
):
    # 1. 実行ユーザーのサーバー管理権限チェック
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message(
            "❌このコマンドを実行するには**サーバー管理**権限が必要です。",
            ephemeral=True
        )
        return

    # 2. 処理が長引く可能性があるため、事前にdefer(応答待機)を設定 (ephemeral=Trueを維持)
    await interaction.response.defer(ephemeral=True)

    guild = interaction.guild
    targets = []
    type_value = type.value  # 選択された値を取得

    try:
        # 3. タイプに応じた対象オブジェクトのリストアップと上限チェック
        if type_value == "チャンネル":
            # カテゴリ以外のチャンネル（テキスト、ボイス、ステージ、フォーラム等）を収集
            targets = [ch for ch in guild.channels if not isinstance(ch, discord.CategoryChannel)]
            if len(targets) > 30:
                targets = targets[:30]
                
        elif type_value == "カテゴリ":
            targets = guild.categories
            if len(targets) > 30:
                targets = targets[:30]
                
        elif type_value == "ロール":
            # @everyone を含むすべてのロール（Bot自身の最高ロールより下、かつ編集可能なもの）
            targets = [role for role in guild.roles if role < guild.me.top_role and not role.is_bot_managed()]
            if len(targets) > 20:
                targets = targets[:20]

        # 4. 既にすべてOFFになっているかの事前チェック
        already_off = True
        for target in targets:
            if type_value in ["チャンネル", "カテゴリ"]:
                # @everyoneに対するチャンネル/カテゴリのオーバーライド確認
                overwrite = target.overwrites_for(guild.default_role)
                if overwrite.use_external_apps is not False:
                    already_off = False
                    break
            elif type_value == "ロール":
                # ロール自体の権限確認
                if target.permissions.use_external_apps:
                    already_off = False
                    break

        if not targets or already_off:
            await interaction.followup.send(
                "✅すでに外部アプリ権限権限がOFFになっています。",
                ephemeral=True
            )
            return

        # 5. 一斉変更処理の実行 (0.8秒ウェイト)
        changed_count = 0
        for target in targets:
            if type_value in ["チャンネル", "カテゴリ"]:
                overwrite = target.overwrites_for(guild.default_role)
                # 既にOFFならスキップして無駄なAPI消費を抑える
                if overwrite.use_external_apps is False:
                    continue
                
                overwrite.use_external_apps = False
                await target.set_permissions(guild.default_role, overwrite=overwrite)
                changed_count += 1
                
            elif type_value == "ロール":
                if not target.permissions.use_external_apps:
                    continue
                
                permissions = target.permissions
                permissions.update(use_external_apps=False)
                await target.edit(permissions=permissions)
                changed_count += 1

            # 1権限変更ごとに0.8秒待機
            await asyncio.sleep(0.8)

        # 6. 正常終了メッセージ
        await interaction.followup.send(
            f"✅{changed_count}個の{type_value}で外部アプリ使用権限をOFFにしました。",
            ephemeral=True
        )

    except Exception as e:
        # 7. 例外エラーハンドリング
        error_name = type(e).__name__
        await interaction.followup.send(
            f"❌エラーが発生しました。{error_name}",
            ephemeral=True
        )

# ===============================
# テキストコマンドでないコマンド類
# ===============================
@bot.tree.context_menu(name="Report Message")
async def report_message(
    interaction: discord.Interaction,
    message: discord.Message
):
    # ===== DM完全拒否 =====
    if interaction.guild is None:
        await interaction.response.send_message(
            "❌ このコマンドはDMでは実行できません。",
            ephemeral=True
        )
        return

    # ===== 念のため：チャンネル不在保険 =====
    if interaction.channel is None:
        await interaction.response.send_message(
            "❌ この場所では実行できません。",
            ephemeral=True
        )
        return

    # ===== 通常処理 =====
    modal = ReportReasonModal(message)
    await interaction.response.send_modal(modal)

# ログの設定
logging.basicConfig(
    level=logging.INFO, # 記録するレベル (INFO, WARNING, ERRORなど)
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler("bot.log", encoding="utf-8"), # ファイルへ出力
        logging.StreamHandler() # コンソールへも出力
    ]
)

logger = logging.getLogger("SecuroWarden")

bot.run("YOUR_BOT_TOKEN_HERE")
