from mitmproxy import http


import base64
import json
import os
import re
import struct
import zlib
import http.client as std_http_client
import ssl
import time
import hashlib
import threading
import zipfile


from types import SimpleNamespace


from pathlib import Path
from email.utils import formatdate




# ======================================================================
# DLS21 8.13 - LAB V2 / CONTROL MOCK
#
# Estado atual:
#   - NEWUSER local
#   - SIGNIN local
#   - Config minimo funcional
#   - TrM.TmP PID 1..12
#   - Prf.DrT.Pl PID 1..12
#   - Prf.DrT.Man.LU indices 0..10
#   - Prf.DrT.Man.Ro indices 0..4
#   - Prf.Sta.ScM = [255] * 10
#   - CAREERINIT local
#   - NFx HID/AID = 258
#   - Car.Mai.Res = 44 slots coerentes
#   - Car.Mai.TIn.Tou = 4 registros de torneio
#   - Tou.Tab / Tou.C minimos e internamente coerentes
#   - CAREERENDMATCH local / op 0x0B
#   - HTTP Date correto
#   - operacoes desconhecidas bloqueadas localmente
#   - LAB V2: suporte nativo a DBv / DBt / DBp / DBl
#   - LAB V2: valida e envia os 3 .dat pelo caminho original da engine
#
# IMPORTANTE:
#
#   O nome correto do bloco de estadio e:
#
#       "Sta"
#
#   com S MAIUSCULO.
#
#   ScM=255 e um teste diagnostico.
#
#   Tabela de modelos .ftm:
#       IDs existentes = 0..100
#
#   Portanto:
#       FUN_0040f30c(255) -> NULL
#
#   e FUN_004121c0(slot, NULL) deve selecionar
#   o modelo default interno correto daquele slot.
#
# Nenhum fallback para o backend antigo.
# ======================================================================




FRONTLINE_HOST = "api.ftpub.net"
FRONTLINE_PATH = "/DLSFrontlineStage/lambdastart_"


TEAM_ID = 258
USER_ID = 1




# ======================================================================
# SAFE SHADOW PROBE - BACKEND REAL / EXACT CLIENT CLONE
#
# O cliente CONTINUA recebendo apenas a resposta local do mock.
# Uma copia da request NEWUSER/SIGNIN e enviada ao backend real somente
# para diagnostico e salva em disco. A resposta real NUNCA e entregue
# ao DLS por este modo.
#
# SHADOW_FORCE_DBV_ZERO=True altera APENAS a copia enviada ao backend:
# o request original do jogo permanece intacto dentro do mitmproxy.
# ======================================================================


SHADOW_REAL_BACKEND = False
SHADOW_OPERATIONS = {"NEWUSER", "SIGNIN"}
SHADOW_MAX_PER_OPERATION = 1
SHADOW_FORCE_DBV_ZERO = True
SHADOW_TIMEOUT_SECONDS = 30
SHADOW_TLS_VERIFY = True


SHADOW_CAPTURE_DIR = Path(__file__).resolve().parent / "real_backend_capture"
_SHADOW_COUNTS = {}








# ======================================================================
# LOCAL DATABASE INJECTION - FULL DATABASE LOCAL
#
# True = valida o trio local e anexa DBv/DBt/DBp/DBl a NEWUSER/SIGNIN
# quando o cliente esta sem banco (DBv=0/ausente) ou com versao diferente.
# False = preserva o comportamento antigo sem full database local.
#
# O shadow probe e independente e permanece DESLIGADO por padrao.
# ======================================================================


ENABLE_LOCAL_DATABASE_INJECTION = True




# ======================================================================
# LAB V2 - DATABASE FULL BOOTSTRAP
#
# Mapeamento confirmado no codigo nativo do DLS21 8.13:
#   DBt -> teams.dat
#   DBp -> players.dat
#   DBl -> teamplayerlinks.dat
#   DBv -> versao comum da database
#
# O mock envia Base64 dos bytes .dat exatamente como estao em disco.
# A propria engine decodifica e grava os arquivos em DOCS:.
# ======================================================================


SCRIPT_DIR = Path(__file__).resolve().parent


DATABASE_DIR_CANDIDATES = [
    # O laboratorio que ja validamos anteriormente tem prioridade.
    SCRIPT_DIR / "database",
    SCRIPT_DIR,
    Path.cwd() / "database",
    Path.cwd(),
]


DATABASE_FILES = {
    "DBt": ("teams.dat", "teams"),
    "DBp": ("players.dat", "players"),
    "DBl": ("teamplayerlinks.dat", "links"),
}


# False = envia somente quando o DBv do cliente for diferente.
# True  = envia em todo NEWUSER/SIGNIN (diagnostico).
FORCE_FULL_DATABASE = False


# O dispatcher nativo prova que o bloco DB pode vir numa resposta TASK.
# A operacao historica exata do primeiro bootstrap ainda nao esta provada;
# o LAB V2 testa apenas os candidatos naturais NEWUSER e SIGNIN.
DATABASE_SEND_OPERATIONS = {"NEWUSER", "SIGNIN"}


_DATABASE_CACHE = None

# Se nenhum trio externo valido estiver disponivel, o mock pode criar em
# memoria um banco LAB minimo e coerente. Isto existe SOMENTE para impedir
# o antigo crash de players.dat ausente durante o bootstrap. Nunca deve ser
# confundido com a database oficial/original do DLS21.
ALLOW_GENERATED_LAB_DATABASE = True
GENERATED_LAB_DB_VERSION = 2



# ======================================================================
# HELPERS
# ======================================================================


def separator(char="=", size=72):
    print(char * size)




def _redact_large_database_fields(obj):
    """Evita despejar megabytes de Base64 no console do mitmproxy."""


    if isinstance(obj, dict):
        cleaned = {}
        for key, value in obj.items():
            if key in ("DBt", "DBp", "DBl", "DBd") and isinstance(value, str):
                cleaned[key] = "<base64 %d chars>" % len(value)
            else:
                cleaned[key] = _redact_large_database_fields(value)
        return cleaned


    if isinstance(obj, list):
        return [_redact_large_database_fields(x) for x in obj]


    return obj




def pretty(obj):
    try:
        return json.dumps(
            _redact_large_database_fields(obj),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
    except Exception:
        return repr(obj)




def decode_bz(value):


    if not isinstance(value, str):
        raise ValueError("b&z nao e string")


    value += "=" * (-len(value) % 4)


    compressed = base64.b64decode(value)


    raw = zlib.decompress(compressed)


    return json.loads(
        raw.decode("utf-8")
    )




def decode_request(flow):


    body = flow.request.get_text(
        strict=False
    )


    if not body:
        raise ValueError(
            "request sem body"
        )


    outer = json.loads(body)


    if (
        isinstance(outer, dict)
        and outer.get("type") == "b&z"
        and isinstance(
            outer.get("values"),
            dict,
        )
        and isinstance(
            outer["values"].get("b&z"),
            str,
        )
    ):


        return decode_bz(
            outer["values"]["b&z"]
        )


    return outer




def response_headers():


    return {


        "Content-Type":
            "application/json; charset=utf-8",


        "Date":
            formatdate(
                timeval=None,
                localtime=False,
                usegmt=True,
            ),


        "Cache-Control":
            "no-cache",


        "Connection":
            "close",
    }




def send_json(
    flow,
    obj,
    status=200,
):


    body = json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


    flow.response = http.Response.make(
        status,
        body,
        response_headers(),
    )




# ======================================================================
# LAB V2 - DATABASE HELPERS
# ======================================================================


def _database_header_info(filename, kind, stored_bytes):
    try:
        raw = zlib.decompress(stored_bytes)
    except Exception as exc:
        raise ValueError("%s nao e zlib valido: %r" % (filename, exc))


    if kind == "players":
        if len(raw) < 12:
            raise ValueError("players.dat menor que header de 12 bytes")
        version = struct.unpack_from("<I", raw, 0)[0]
        count = struct.unpack_from("<I", raw, 8)[0]
        expected = 12 + count * 0xB4
    elif kind == "teams":
        if len(raw) < 12:
            raise ValueError("teams.dat menor que header de 12 bytes")
        version = struct.unpack_from("<I", raw, 0)[0]
        count = struct.unpack_from("<I", raw, 8)[0]
        expected = 12 + count * 0x1AC
    elif kind == "links":
        if len(raw) < 8:
            raise ValueError("teamplayerlinks.dat menor que header de 8 bytes")
        version = struct.unpack_from("<I", raw, 0)[0]
        count = struct.unpack_from("<I", raw, 4)[0]
        expected = 8 + count * 0x148
    else:
        raise ValueError("tipo de banco desconhecido: %r" % kind)


    if count <= 0:
        raise ValueError("%s tem count invalido: %d" % (filename, count))
    if len(raw) != expected:
        raise ValueError(
            "%s estrutura invalida: raw=%d esperado=%d count=%d"
            % (filename, len(raw), expected, count)
        )


    return {
        "version": version,
        "count": count,
        "stored_size": len(stored_bytes),
        "raw_size": len(raw),
        "adler32": zlib.adler32(raw, 1) & 0xFFFFFFFF,
    }




def _find_database_dir():
    env_dir = os.environ.get("DLS21_DB_DIR")
    candidates = []
    if env_dir:
        candidates.append(Path(env_dir))
    candidates.extend(DATABASE_DIR_CANDIDATES)


    for candidate in candidates:
        try:
            if all(
                (candidate / filename).is_file()
                for filename, _kind in DATABASE_FILES.values()
            ):
                return candidate
        except Exception:
            pass
    return None




def _validate_cross_database(encoded):
    """Cruza IDs entre players.dat, teams.dat e teamplayerlinks.dat."""
    players_raw = zlib.decompress(base64.b64decode(encoded["DBp"]))
    teams_raw = zlib.decompress(base64.b64decode(encoded["DBt"]))
    links_raw = zlib.decompress(base64.b64decode(encoded["DBl"]))


    player_count = struct.unpack_from("<I", players_raw, 8)[0]
    team_count = struct.unpack_from("<I", teams_raw, 8)[0]
    link_count = struct.unpack_from("<I", links_raw, 4)[0]


    pids = [
        struct.unpack_from("<H", players_raw, 12 + i * 0xB4 + 0x70)[0]
        for i in range(player_count)
    ]
    tids = [
        struct.unpack_from("<I", teams_raw, 12 + i * 0x1AC)[0]
        for i in range(team_count)
    ]


    if len(set(pids)) != len(pids):
        raise ValueError("players.dat contem PID duplicado")
    if len(set(tids)) != len(tids):
        raise ValueError("teams.dat contem TID duplicado")


    pid_set = set(pids)
    tid_set = set(tids)
    missing_pids = set()
    missing_tids = set()
    referenced_pids = set()


    for i in range(link_count):
        rec = 8 + i * 0x148
        tid = struct.unpack_from("<I", links_raw, rec)[0]
        member_count = struct.unpack_from("<I", links_raw, rec + 4)[0]
        if member_count > 40:
            raise ValueError(
                "teamplayerlinks.dat TID=%d tem count=%d (>40)"
                % (tid, member_count)
            )
        if tid not in tid_set:
            missing_tids.add(tid)
        for slot in range(member_count):
            pid = struct.unpack_from(
                "<I", links_raw, rec + 8 + slot * 8 + 4
            )[0]
            if not pid:
                continue
            referenced_pids.add(pid)
            if pid not in pid_set:
                missing_pids.add(pid)


    if missing_tids:
        raise ValueError(
            "links apontam para TIDs ausentes: %s"
            % sorted(missing_tids)[:20]
        )
    if missing_pids:
        raise ValueError(
            "links apontam para PIDs ausentes: %s"
            % sorted(missing_pids)[:20]
        )


    return {
        "unique_players": len(pid_set),
        "unique_teams": len(tid_set),
        "link_records": link_count,
        "referenced_players": len(referenced_pids),
    }




def _write_utf16_fixed(buf, offset, size, text):
    data = str(text).encode("utf-16le")
    # Reserva 2 bytes para NUL UTF-16 e nunca corta no meio de um code unit.
    data = data[:max(0, size - 2)]
    data = data[:len(data) - (len(data) % 2)]
    buf[offset:offset + len(data)] = data



def _build_generated_lab_database():
    """
    Gera um trio LAB minimo, inteiramente em memoria.

    Objetivo: evitar que DBv=0 + ausencia dos .dat leve o loader nativo a
    dereferenciar NULL. Este banco NAO e a database oficial do DLS21.
    """
    version = GENERATED_LAB_DB_VERSION
    pids = list(FALLBACK_PLAYER_IDS) if "FALLBACK_PLAYER_IDS" in globals() else (list(range(1, 18)) + [2505])

    # ---------------- players.dat ----------------
    players_raw = bytearray(12 + len(pids) * 0xB4)
    struct.pack_into("<III", players_raw, 0, version, 0, len(pids))

    position_codes = [0, 1, 2, 5, 6, 8, 14, 16, 17, 19, 0, 1, 2, 5, 6, 14, 19, 11]
    for i, pid in enumerate(pids):
        rec_off = 12 + i * 0xB4
        rec = memoryview(players_raw)[rec_off:rec_off + 0xB4]

        if pid == 2505:
            first, last, nick = "Ivan", "Rakitic", "I. Rakitic"
            pos, foot = 11, 1
            values = {
                0x8A: 710,  # STR
                0x8C: 750,  # STA
                0x8E: 730,  # ACC
                0x90: 720,  # SPE
                0x92: 630,  # TAC
                0x94: 850,  # CON
                0x96: 860,  # SHO
                0x98: 860,  # PAS
                0x9A: 690,
                0x9C: 700,
            }
        else:
            first, last, nick = "LAB", "PLAYER%d" % pid, "L.%d" % pid
            pos = position_codes[i % len(position_codes)]
            foot = 1 if (i % 3) == 0 else 0
            values = {off: 700 for off in range(0x8A, 0x9E, 2)}

        # memoryview nao aceita nossa helper diretamente em todas as versoes,
        # entao escrevemos no buffer principal usando offsets absolutos.
        _write_utf16_fixed(players_raw, rec_off + 0x00, 0x20, first)
        _write_utf16_fixed(players_raw, rec_off + 0x20, 0x30, last)
        _write_utf16_fixed(players_raw, rec_off + 0x50, 0x20, nick)
        struct.pack_into("<H", players_raw, rec_off + 0x70, int(pid))
        struct.pack_into("<H", players_raw, rec_off + 0x7C, 184)
        struct.pack_into("<H", players_raw, rec_off + 0x80, int(pos))
        struct.pack_into("<H", players_raw, rec_off + 0x88, int(foot))
        for off, value in values.items():
            struct.pack_into("<H", players_raw, rec_off + off, int(value))

    # ---------------- teams.dat ----------------
    teams_raw = bytearray(12 + 0x1AC)
    struct.pack_into("<III", teams_raw, 0, version, 0, 1)
    struct.pack_into("<I", teams_raw, 12, TEAM_ID)

    # ---------------- teamplayerlinks.dat ----------------
    links_raw = bytearray(8 + 0x148)
    struct.pack_into("<II", links_raw, 0, version, 1)
    rec = 8
    struct.pack_into("<I", links_raw, rec + 0x00, TEAM_ID)
    struct.pack_into("<I", links_raw, rec + 0x04, min(len(pids), 40))
    for slot, pid in enumerate(pids[:40]):
        slot_off = rec + 0x08 + slot * 8
        # metadata A/B/C = 0; PID em +4.
        struct.pack_into("<I", links_raw, slot_off + 0x04, int(pid))

    raw_map = {
        "DBp": ("players.dat", "players", bytes(players_raw)),
        "DBt": ("teams.dat", "teams", bytes(teams_raw)),
        "DBl": ("teamplayerlinks.dat", "links", bytes(links_raw)),
    }
    encoded = {}
    info_by_field = {}
    for field, (filename, kind, raw) in raw_map.items():
        stored = zlib.compress(raw)
        encoded[field] = base64.b64encode(stored).decode("ascii")
        info_by_field[field] = _database_header_info(filename, kind, stored)

    cross = _validate_cross_database(encoded)
    database = {
        "dir": "<LAB GERADO EM MEMORIA>",
        "version": version,
        "encoded": encoded,
        "info": info_by_field,
        "cross": cross,
        "generated": True,
    }

    print()
    separator("!")
    print("[DBV2] FALLBACK LAB GERADO EM MEMORIA")
    print("[DBV2] ATENCAO: NAO E DATABASE OFICIAL/ORIGINAL")
    print("[DBV2] DBv=%d | players=%d | teams=1 | links=1 | TID=%d" % (version, len(pids), TEAM_ID))
    print("[DBV2] Motivo: nenhum trio externo valido foi carregado.")
    print("[DBV2] O objetivo deste fallback e impedir o crash de bootstrap sem players.dat.")
    separator("!")
    print()
    return database



def load_full_database():
    """Valida os 3 .dat e prepara DBt/DBp/DBl sem alterar os originais."""
    global _DATABASE_CACHE


    if _DATABASE_CACHE is False:
        return None
    if isinstance(_DATABASE_CACHE, dict):
        return _DATABASE_CACHE


    db_dir = _find_database_dir()
    if db_dir is None:
        print("[DBV2] database AUSENTE")
        print("[DBV2] Procurei em:")
        for candidate in DATABASE_DIR_CANDIDATES:
            print("[DBV2]  -", candidate)
        print("[DBV2] Tambem aceita a variavel DLS21_DB_DIR.")
        if ALLOW_GENERATED_LAB_DATABASE:
            _DATABASE_CACHE = _build_generated_lab_database()
            return _DATABASE_CACHE
        _DATABASE_CACHE = False
        return None


    info_by_field = {}
    encoded = {}
    versions = set()


    try:
        for field, (filename, kind) in DATABASE_FILES.items():
            path = db_dir / filename
            stored = path.read_bytes()
            info = _database_header_info(filename, kind, stored)
            info_by_field[field] = info
            encoded[field] = base64.b64encode(stored).decode("ascii")
            versions.add(info["version"])


        if len(versions) != 1:
            raise ValueError(
                "versoes diferentes entre teams/players/links: %r"
                % sorted(versions)
            )


        version = next(iter(versions))
        cross = _validate_cross_database(encoded)
        _DATABASE_CACHE = {
            "dir": db_dir,
            "version": version,
            "encoded": encoded,
            "info": info_by_field,
            "cross": cross,
        }


        print()
        separator("+")
        print("[DBV2] DATABASE VALIDADA")
        print("[DBV2] pasta =", db_dir)
        print("[DBV2] DBv   =", version)
        print(
            "[DBV2] teams=%d | players=%d | links=%d"
            % (
                info_by_field["DBt"]["count"],
                info_by_field["DBp"]["count"],
                info_by_field["DBl"]["count"],
            )
        )
        print(
            "[DBV2] bytes .dat: teams=%d | players=%d | links=%d"
            % (
                info_by_field["DBt"]["stored_size"],
                info_by_field["DBp"]["stored_size"],
                info_by_field["DBl"]["stored_size"],
            )
        )
        print(
            "[DBV2] Adler-32 RAW: TCkSm=0x%08X | PCkSm=0x%08X | LCkSm=0x%08X"
            % (
                info_by_field["DBt"]["adler32"],
                info_by_field["DBp"]["adler32"],
                info_by_field["DBl"]["adler32"],
            )
        )
        print(
            "[DBV2] cruzamento: players=%d | teams=%d | link_records=%d | referenced_players=%d"
            % (
                cross["unique_players"],
                cross["unique_teams"],
                cross["link_records"],
                cross["referenced_players"],
            )
        )
        separator("+")
        print()
        return _DATABASE_CACHE


    except Exception as exc:
        print()
        separator("!")
        print("[DBV2] DATABASE REJEITADA:", repr(exc))
        print("[DBV2] O trio externo nao sera enviado ao cliente.")
        separator("!")
        print()
        if ALLOW_GENERATED_LAB_DATABASE:
            _DATABASE_CACHE = _build_generated_lab_database()
            return _DATABASE_CACHE
        _DATABASE_CACHE = False
        return None




def _normalize_dbv(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None




def inject_full_database(response, client_values, operation):
    """Anexa DBv/DBt/DBp/DBl quando o cliente precisa do full DB."""


    if not ENABLE_LOCAL_DATABASE_INJECTION:
        print(
            "[DBV2] %s: INJECAO LOCAL DESATIVADA POR CODIGO; "
            "DBv/DBt/DBp/DBl NAO serao enviados."
            % operation
        )
        return False


    if operation not in DATABASE_SEND_OPERATIONS:
        return False


    database = load_full_database()
    if not database:
        return False


    server_dbv = database["version"]
    client_dbv = _normalize_dbv(client_values.get("DBv"))
    should_send = (
        FORCE_FULL_DATABASE
        or client_dbv is None
        or client_dbv == 0
        or client_dbv != server_dbv
    )


    if not should_send:
        print(
            "[DBV2] %s: cliente DBv=%s ja coincide com DBv=%s; full DB nao enviada."
            % (operation, client_dbv, server_dbv)
        )
        return False


    response["DBv"] = server_dbv
    response.update(database["encoded"])


    print()
    separator("+")
    print("[DBV2] FULL DATABASE ANEXADA A", operation)
    print("[DBV2] cliente DBv =", client_dbv)
    print("[DBV2] servidor DBv =", server_dbv)
    print(
        "[DBV2] DBt/DBp/DBl Base64 = %d / %d / %d chars"
        % (
            len(database["encoded"]["DBt"]),
            len(database["encoded"]["DBp"]),
            len(database["encoded"]["DBl"]),
        )
    )
    print("[DBV2] A engine do DLS deve decodificar e gravar os .dat.")
    separator("+")
    print()
    return True






# ======================================================================
# SAFE SHADOW PROBE - HELPERS
# ======================================================================


def _shadow_json_bytes(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")




def _shadow_patch_dbv_zero_in_json_bytes(raw_bytes):
    """
    Troca SOMENTE o valor numerico de "DBv" por 0, preservando os demais
    bytes do JSON (ordem, espacos, nomes e valores).


    Retorna (bytes_novos, quantidade_de_substituicoes).
    """
    pattern = re.compile(rb'("DBv"\s*:\s*)-?\d+')
    return pattern.subn(rb'\g<1>0', raw_bytes, count=1)




def _shadow_prepare_request(flow, request_data):
    """
    Retorna (body_bytes, decoded_request_copy).


    MODO CLONE:
      - parte dos bytes EXATOS capturados do telefone;
      - altera somente DBv na COPIA enviada ao backend real;
      - se houver envelope b&z, preserva o JSON externo byte-a-byte e
        substitui somente o valor Base64 depois de editar DBv no JSON interno;
      - o request original do jogo nunca e modificado.
    """
    body = flow.request.raw_content or b""
    decoded_copy = json.loads(json.dumps(request_data))


    if (
        SHADOW_FORCE_DBV_ZERO
        and isinstance(decoded_copy, dict)
        and isinstance(decoded_copy.get("values"), dict)
    ):
        decoded_copy["values"]["DBv"] = 0


    if not SHADOW_FORCE_DBV_ZERO:
        return body, decoded_copy


    # 1) Envelope b&z: altera apenas o blob Base64 no JSON externo original.
    #    O JSON interno tambem e preservado byte-a-byte, exceto pelo numero DBv.
    try:
        outer = json.loads(body.decode("utf-8", errors="strict"))
    except Exception:
        outer = None


    if (
        isinstance(outer, dict)
        and outer.get("type") == "b&z"
        and isinstance(outer.get("values"), dict)
        and isinstance(outer["values"].get("b&z"), str)
    ):
        # Localiza especificamente a CHAVE "b&z" (nao o valor de "type").
        match = re.search(
            rb'"b&z"\s*:\s*"([A-Za-z0-9+/=]*)"',
            body,
        )
        if match:
            try:
                encoded = match.group(1)
                compressed = base64.b64decode(
                    encoded + b"=" * (-len(encoded) % 4)
                )
                inner_raw = zlib.decompress(compressed)
                inner_patched, changed = _shadow_patch_dbv_zero_in_json_bytes(
                    inner_raw
                )
                if changed == 1:
                    repacked = zlib.compress(inner_patched)
                    replacement = base64.b64encode(repacked)
                    body_patched = (
                        body[:match.start(1)]
                        + replacement
                        + body[match.end(1):]
                    )
                    print(
                        "[SHADOW] clone body: envelope b&z preservado; "
                        "somente DBv interno foi alterado para 0."
                    )
                    return body_patched, decoded_copy
            except Exception as exc:
                print(
                    "[SHADOW] clone b&z byte-preserving falhou; "
                    "tentando fallback JSON:",
                    repr(exc),
                )


        # Fallback seguro: reconstroi somente se o caminho byte-preserving falhou.
        try:
            packed = zlib.compress(_shadow_json_bytes(decoded_copy))
            outer["values"]["b&z"] = base64.b64encode(packed).decode("ascii")
            print("[SHADOW] clone body: fallback b&z reserializado.")
            return _shadow_json_bytes(outer), decoded_copy
        except Exception:
            return body, decoded_copy


    # 2) JSON direto: troca apenas os digitos de DBv nos bytes originais.
    body_patched, changed = _shadow_patch_dbv_zero_in_json_bytes(body)
    if changed == 1:
        print(
            "[SHADOW] clone body: JSON direto preservado; "
            "somente DBv foi alterado para 0."
        )
        return body_patched, decoded_copy


    # Se nao reconheceu DBv, nao transforma o request.
    print(
        "[SHADOW] AVISO: DBv nao localizado nos bytes; "
        "copia enviada sem alterar o body."
    )
    return body, decoded_copy




def _shadow_headers(flow, body_len):
    """
    Clona os headers observados no request REAL do telefone.


    Diferencas intencionais:
      - Content-Length e recalculado porque DBv=0 pode mudar o tamanho do body;
      - Proxy-Connection e removido caso o proxy o tenha inserido;
      - nenhum Connection: close e inventado;
      - Host, User-Agent, Accept-Encoding e demais headers sao preservados.


    O Java original adiciona Accept-Encoding: identity. Se por algum motivo esse
    header nao chegou ao flow do mitmproxy, ele e reposto como identity.
    """
    headers = {}
    content_length_key = None


    for key, value in flow.request.headers.items():
        lower = key.lower()


        if lower == "proxy-connection":
            continue


        if lower == "transfer-encoding":
            # O FTTHttpDownloadManager original envia Content-Length no POST.
            # Evita conflito caso alguma camada do proxy tenha convertido isso.
            continue


        if lower == "content-length":
            content_length_key = key
            continue


        headers[key] = value


    # Preserva a capitalizacao observada, quando disponivel.
    headers[content_length_key or "Content-Length"] = str(body_len)


    if not any(k.lower() == "accept-encoding" for k in headers):
        headers["Accept-Encoding"] = "identity"


    return headers




def _shadow_headers_for_log(headers):
    return {str(k): str(v) for k, v in headers.items()}


def _shadow_decode_response(raw_bytes):
    """
    Tenta interpretar a resposta como JSON e, se existir envelope b&z,
    tambem devolve o objeto interno descompactado.
    """
    result = {
        "text": None,
        "outer": None,
        "inner": None,
    }


    try:
        result["text"] = raw_bytes.decode("utf-8")
    except Exception:
        return result


    try:
        outer = json.loads(result["text"])
        result["outer"] = outer
    except Exception:
        return result


    # A resposta do servidor nao precisa trazer type="b&z".
    # O codigo nativo original procura diretamente values["b&z"] e values["el"].
    if (
        isinstance(outer, dict)
        and isinstance(outer.get("values"), dict)
        and isinstance(outer["values"].get("b&z"), str)
    ):
        try:
            result["inner"] = decode_bz(
                outer["values"]["b&z"]
            )
            expected_len = outer["values"].get("el")
            if expected_len is not None:
                print("[SHADOW] resposta envelope: values.el =", expected_len)
        except Exception as exc:
            print("[SHADOW] resposta b&z, mas decode falhou:", repr(exc))


    return result




def _shadow_find_dicts_with_db(obj, found=None):
    if found is None:
        found = []


    if isinstance(obj, dict):
        keys = set(obj.keys())
        if keys.intersection({"DBv", "DBt", "DBp", "DBl"}):
            found.append(obj)
        for value in obj.values():
            _shadow_find_dicts_with_db(value, found)


    elif isinstance(obj, list):
        for value in obj:
            _shadow_find_dicts_with_db(value, found)


    return found




def _shadow_extract_database(obj, capture_dir):
    """
    Procura DBt/DBp/DBl em qualquer dict da resposta e salva somente
    campos Base64 que decodificam para .dat zlib estruturalmente validos.
    """
    if obj is None:
        return False


    candidates = _shadow_find_dicts_with_db(obj)
    if not candidates:
        return False


    mapping = {
        "DBt": ("teams.dat", "teams"),
        "DBp": ("players.dat", "players"),
        "DBl": ("teamplayerlinks.dat", "links"),
    }


    extracted_any = False


    for index, candidate in enumerate(candidates):
        present = [k for k in ("DBv", "DBt", "DBp", "DBl") if k in candidate]
        print("[SHADOW] bloco DB candidato %d: %s" % (index, present))


        if "DBv" in candidate:
            print("[SHADOW] DBv REAL =", candidate.get("DBv"))


        for field, (filename, kind) in mapping.items():
            value = candidate.get(field)
            if not isinstance(value, str) or not value:
                continue


            try:
                stored = base64.b64decode(value + "=" * (-len(value) % 4))
                info = _database_header_info(filename, kind, stored)
            except Exception as exc:
                print(
                    "[SHADOW] %s presente, mas nao validou como %s: %r"
                    % (field, filename, exc)
                )
                continue


            out = capture_dir / filename
            out.write_bytes(stored)
            extracted_any = True


            print(
                "[SHADOW] EXTRAIDO %s -> %s | version=%s count=%s stored=%s raw=%s"
                % (
                    field,
                    out,
                    info["version"],
                    info["count"],
                    info["stored_size"],
                    info["raw_size"],
                )
            )


    return extracted_any




def _shadow_snapshot_flow(flow):
    """
    Copia somente os dados imutaveis da request que o shadow precisa.
    Isso evita usar o objeto mitmproxy Flow fora da thread principal.
    """
    req = flow.request
    headers = {str(k): str(v) for k, v in req.headers.items()}
    request_snapshot = SimpleNamespace(
        raw_content=bytes(req.raw_content or b""),
        headers=headers,
        method=str(req.method),
        scheme=str(req.scheme or "https"),
        host=str(req.host),
        port=int(req.port or (443 if (req.scheme or "https").lower() == "https" else 80)),
        path=str(req.path),
        http_version=getattr(req, "http_version", None),
    )
    return SimpleNamespace(request=request_snapshot)




def _start_shadow_probe_async(flow, request_data, operation):
    """
    Dispara o shadow em background para NUNCA atrasar NEWUSER/SIGNIN local.
    O jogo recebe a resposta mock imediatamente; a consulta real roda isolada.
    """
    if not SHADOW_REAL_BACKEND or operation not in SHADOW_OPERATIONS:
        return


    snapshot = _shadow_snapshot_flow(flow)
    request_copy = json.loads(json.dumps(request_data))


    thread = threading.Thread(
        target=shadow_probe_real_backend,
        args=(snapshot, request_copy, operation),
        name="DLS21-Shadow-%s" % operation,
        daemon=True,
    )
    thread.start()
    print("[SHADOW] probe iniciado em background; resposta local NAO sera atrasada.")




def shadow_probe_real_backend(flow, request_data, operation):
    """
    Envia uma COPIA controlada ao backend real.


    IMPORTANTE:
      - flow.response NAO e tocado aqui.
      - a resposta real e apenas gravada/analisada.
      - o handler local NEWUSER/SIGNIN continua respondendo ao jogo.
    """
    if not SHADOW_REAL_BACKEND:
        return


    if operation not in SHADOW_OPERATIONS:
        return


    count = _SHADOW_COUNTS.get(operation, 0)
    if count >= SHADOW_MAX_PER_OPERATION:
        print(
            "[SHADOW] %s: limite %d atingido; backend real nao chamado novamente."
            % (operation, SHADOW_MAX_PER_OPERATION)
        )
        return


    _SHADOW_COUNTS[operation] = count + 1


    timestamp = time.strftime("%Y%m%d_%H%M%S")
    millis = int((time.time() % 1) * 1000)
    capture_dir = SHADOW_CAPTURE_DIR / (
        "%s_%s_%03d" % (timestamp, operation, millis)
    )
    capture_dir.mkdir(parents=True, exist_ok=True)


    try:
        body, shadow_request = _shadow_prepare_request(
            flow,
            request_data,
        )


        # Salva os bytes originais do telefone e a copia modificada.
        original_body = flow.request.raw_content or b""
        (capture_dir / "request_original.bin").write_bytes(original_body)
        (capture_dir / "request_shadow.bin").write_bytes(body)
        (capture_dir / "request_original_decoded.json").write_text(
            json.dumps(
                request_data,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        (capture_dir / "request_shadow_decoded.json").write_text(
            json.dumps(
                shadow_request,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )


        request_sha = hashlib.sha256(body).hexdigest()
        original_sha = hashlib.sha256(original_body).hexdigest()


        headers = _shadow_headers(flow, len(body))
        original_headers = {str(k): str(v) for k, v in flow.request.headers.items()}


        (capture_dir / "request_original_headers.json").write_text(
            json.dumps(original_headers, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (capture_dir / "request_shadow_headers.json").write_text(
            json.dumps(_shadow_headers_for_log(headers), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (capture_dir / "request_meta.json").write_text(
            json.dumps(
                {
                    "method": flow.request.method,
                    "scheme": flow.request.scheme,
                    "host": flow.request.host,
                    "port": flow.request.port,
                    "path": flow.request.path,
                    "http_version": getattr(flow.request, "http_version", None),
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )


        print()
        separator("@")
        print("[SHADOW] BACKEND REAL - COPIA DIAGNOSTICA")
        print("[SHADOW] operation =", operation)
        print("[SHADOW] host      =", flow.request.host)
        print("[SHADOW] path      =", flow.request.path)
        print("[SHADOW] DBv copia =", (
            shadow_request.get("values", {}).get("DBv")
            if isinstance(shadow_request, dict)
            else None
        ))
        print("[SHADOW] bytes original =", len(original_body))
        print("[SHADOW] bytes shadow   =", len(body))
        print("[SHADOW] sha256 original=", original_sha)
        print("[SHADOW] sha256 shadow  =", request_sha)
        print("[SHADOW] headers clonados= SIM; so Content-Length e recalculado")
        print("[SHADOW] Accept-Encoding =", next((v for k, v in headers.items() if k.lower() == "accept-encoding"), None))
        print("[SHADOW] User-Agent      =", next((v for k, v in headers.items() if k.lower() == "user-agent"), None))
        print("[SHADOW] pasta     =", capture_dir)
        print("[SHADOW] A resposta REAL NAO sera entregue ao DLS.")
        separator("@")


        if SHADOW_TLS_VERIFY:
            context = ssl.create_default_context()
        else:
            context = ssl._create_unverified_context()


        scheme = (flow.request.scheme or "https").lower()
        port = flow.request.port or (443 if scheme == "https" else 80)


        if scheme == "https":
            conn = std_http_client.HTTPSConnection(
                flow.request.host,
                port,
                timeout=SHADOW_TIMEOUT_SECONDS,
                context=context,
            )
        else:
            conn = std_http_client.HTTPConnection(
                flow.request.host,
                port,
                timeout=SHADOW_TIMEOUT_SECONDS,
            )


        conn.request(
            flow.request.method,
            flow.request.path,
            body=body,
            headers=headers,
        )


        response = conn.getresponse()
        raw = response.read()
        response_headers_real = dict(response.getheaders())
        status = response.status
        reason = response.reason
        conn.close()


        (capture_dir / "response_real.bin").write_bytes(raw)
        (capture_dir / "response_headers.json").write_text(
            json.dumps(
                {
                    "status": status,
                    "reason": reason,
                    "headers": response_headers_real,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )


        decoded = _shadow_decode_response(raw)


        if decoded["text"] is not None:
            (capture_dir / "response_real.txt").write_text(
                decoded["text"],
                encoding="utf-8",
            )


        if decoded["outer"] is not None:
            (capture_dir / "response_outer.json").write_text(
                json.dumps(
                    decoded["outer"],
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )


        if decoded["inner"] is not None:
            (capture_dir / "response_inner.json").write_text(
                json.dumps(
                    decoded["inner"],
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )


        print()
        separator("@")
        print("[SHADOW] RESPOSTA REAL CAPTURADA")
        print("[SHADOW] HTTP =", status, reason)
        print("[SHADOW] bytes =", len(raw))
        print("[SHADOW] sha256 =", hashlib.sha256(raw).hexdigest())


        display_obj = (
            decoded["inner"]
            if decoded["inner"] is not None
            else decoded["outer"]
        )


        if display_obj is not None:
            print("[SHADOW] JSON REAL (campos DB redigidos no console):")
            print(pretty(display_obj))


            extracted = _shadow_extract_database(
                display_obj,
                capture_dir,
            )


            if extracted:
                print("[SHADOW] *** BANCO REAL EXTRAIDO E VALIDADO ***")
            else:
                print("[SHADOW] nenhum trio .dat valido extraido desta resposta.")
        else:
            print("[SHADOW] resposta nao era JSON UTF-8 reconhecivel.")


        print("[SHADOW] resposta continua ISOLADA do cliente.")
        separator("@")
        print()


    except Exception as exc:
        (capture_dir / "shadow_error.txt").write_text(
            repr(exc),
            encoding="utf-8",
        )
        print()
        separator("@")
        print("[SHADOW] FALHA AO CONSULTAR BACKEND REAL:", repr(exc))
        print("[SHADOW] O MOCK LOCAL CONTINUA funcionando normalmente.")
        print("[SHADOW] erro salvo em:", capture_dir / "shadow_error.txt")
        separator("@")
        print()




# ======================================================================
# MUSIC / PLAYLIST OFFLINE
#
# A v8.13 le Config.Music com arrays indexados:
# TrackCount, InitialBootTrack, Enabled, FileName, ArtistName, TrackName.
# A engine acrescenta PKG:/data/audio/ ao FileName. Portanto o mock envia
# somente o caminho relativo dentro de assets/data/audio/.
#
# Prioridade:
#   1) DLS21_MUSIC_JSON (variavel de ambiente)
#   2) music.json ao lado deste script
#   3) descoberta conservadora em DLS21_APK / DLS21.apk / base.apk
# ======================================================================


_MUSIC_CACHE = None




def _clean_music_filename(value):
    if not isinstance(value, str):
        return None
    value = value.strip().replace("\\", "/")
    lower = value.lower()
    for prefix in ("pkg:/data/audio/", "assets/data/audio/", "data/audio/"):
        if lower.startswith(prefix):
            value = value[len(prefix):]
            lower = value.lower()
            break
    value = value.lstrip("/")
    parts = [p for p in value.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)




def _music_tracks_to_engine(tracks, initial_boot_track=0):
    clean = []
    for item in tracks:
        if isinstance(item, str):
            item = {"FileName": item}
        if not isinstance(item, dict):
            continue
        filename = _clean_music_filename(item.get("FileName") or item.get("file"))
        if not filename:
            continue
        clean.append({
            "Enabled": bool(item.get("Enabled", item.get("enabled", True))),
            "FileName": filename,
            "ArtistName": str(item.get("ArtistName", item.get("artist", "")) or ""),
            "TrackName": str(item.get("TrackName", item.get("title", Path(filename).stem)) or Path(filename).stem),
        })


    if not clean:
        return None


    try:
        initial = int(initial_boot_track)
    except (TypeError, ValueError):
        initial = 0
    if initial < 0 or initial >= len(clean):
        initial = 0


    return {
        "TrackCount": len(clean),
        "InitialBootTrack": initial,
        "Enabled": [x["Enabled"] for x in clean],
        "FileName": [x["FileName"] for x in clean],
        "ArtistName": [x["ArtistName"] for x in clean],
        "TrackName": [x["TrackName"] for x in clean],
    }




def _load_music_json(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print("[MUSIC] music.json invalido:", repr(exc))
        return None


    if isinstance(data, list):
        return _music_tracks_to_engine(data, 0)


    if not isinstance(data, dict):
        return None


    tracks = data.get("Tracks") or data.get("tracks")
    if isinstance(tracks, list):
        return _music_tracks_to_engine(
            tracks,
            data.get("InitialBootTrack", data.get("initial_boot_track", 0)),
        )


    # Tambem aceita diretamente a forma que a engine espera.
    filenames = data.get("FileName")
    if isinstance(filenames, list):
        enabled = data.get("Enabled") or []
        artists = data.get("ArtistName") or []
        names = data.get("TrackName") or []
        tracks = []
        for i, filename in enumerate(filenames):
            tracks.append({
                "FileName": filename,
                "Enabled": enabled[i] if i < len(enabled) else True,
                "ArtistName": artists[i] if i < len(artists) else "",
                "TrackName": names[i] if i < len(names) else Path(str(filename)).stem,
            })
        return _music_tracks_to_engine(
            tracks,
            data.get("InitialBootTrack", 0),
        )


    return None




def _discover_music_from_apk():
    candidates = []
    env_apk = os.environ.get("DLS21_APK")
    if env_apk:
        candidates.append(Path(env_apk))
    candidates.extend([
        SCRIPT_DIR / "DLS21.apk",
        SCRIPT_DIR / "DLS21_8.13.apk",
        SCRIPT_DIR / "base.apk",
    ])


    # Somente arquivos de audio diretamente em data/audio/. Isso evita
    # transformar milhares de SFX de subpastas em playlist.
    audio_exts = {".mp3", ".ogg", ".m4a", ".aac", ".opus", ".wav"}
    banks = {"se.bnk", "crowd.bnk", "commentary.bnk"}


    for apk in candidates:
        if not apk.is_file():
            continue
        try:
            tracks = []
            with zipfile.ZipFile(apk, "r") as zf:
                for name in zf.namelist():
                    normalized = name.replace("\\", "/")
                    prefix = "assets/data/audio/"
                    if not normalized.lower().startswith(prefix):
                        continue
                    rel = normalized[len(prefix):]
                    if not rel or "/" in rel:
                        continue
                    if rel.lower() in banks:
                        continue
                    if Path(rel).suffix.lower() not in audio_exts:
                        continue
                    tracks.append({
                        "Enabled": True,
                        "FileName": rel,
                        "ArtistName": "",
                        "TrackName": Path(rel).stem,
                    })


            if tracks:
                tracks.sort(key=lambda x: x["FileName"].lower())
                print("[MUSIC] APK =", apk)
                print("[MUSIC] faixas candidatas na raiz data/audio =", len(tracks))
                return _music_tracks_to_engine(tracks, 0)
        except Exception as exc:
            print("[MUSIC] falha ao examinar APK", apk, repr(exc))


    return None




def load_music_config():
    global _MUSIC_CACHE
    if _MUSIC_CACHE is False:
        return None
    if isinstance(_MUSIC_CACHE, dict):
        return _MUSIC_CACHE


    candidates = []
    env_json = os.environ.get("DLS21_MUSIC_JSON")
    if env_json:
        candidates.append(Path(env_json))
    candidates.append(SCRIPT_DIR / "music.json")


    for path in candidates:
        if path.is_file():
            music = _load_music_json(path)
            if music:
                _MUSIC_CACHE = music
                print("[MUSIC] playlist carregada de", path)
                print("[MUSIC] TrackCount =", music["TrackCount"])
                return music


    music = _discover_music_from_apk()
    if music:
        _MUSIC_CACHE = music
        return music


    print("[MUSIC] playlist nao configurada; o jogo continua com fallback interno.")
    _MUSIC_CACHE = False
    return None




# ======================================================================
# DATABASE -> PERFIL LOCAL
# Usa o teamplayerlinks.dat real para montar TmP/DrT quando disponivel.
# ======================================================================


FALLBACK_PLAYER_IDS = list(range(1, 18)) + [2505]




def database_player_ids_for_team(team_id=TEAM_ID):
    database = load_full_database()
    if not database:
        return list(FALLBACK_PLAYER_IDS)


    try:
        players_stored = base64.b64decode(database["encoded"]["DBp"])
        links_stored = base64.b64decode(database["encoded"]["DBl"])
        players_raw = zlib.decompress(players_stored)
        links_raw = zlib.decompress(links_stored)


        player_count = struct.unpack_from("<I", players_raw, 8)[0]
        player_order = [
            struct.unpack_from("<H", players_raw, 12 + i * 0xB4 + 0x70)[0]
            for i in range(player_count)
        ]
        valid_pids = set(player_order)


        link_count = struct.unpack_from("<I", links_raw, 4)[0]
        for i in range(link_count):
            rec = 8 + i * 0x148
            tid = struct.unpack_from("<I", links_raw, rec)[0]
            if tid != team_id:
                continue
            count = min(struct.unpack_from("<I", links_raw, rec + 4)[0], 40)
            pids = []
            for slot in range(count):
                pid = struct.unpack_from("<I", links_raw, rec + 8 + slot * 8 + 4)[0]
                if pid and pid in valid_pids and pid not in pids:
                    pids.append(pid)
            if pids:
                print("[DBV2] perfil usando roster do teamplayerlinks.dat:", pids)
                return pids


        # Um banco oficial pode nao ter um link record para o TEAM_ID local 258.
        # Nesse caso ainda usamos PIDs REAIS do players.dat, nunca PIDs inventados.
        fallback_from_db = [pid for pid in player_order if pid][:18]
        if fallback_from_db:
            print(
                "[DBV2] TID %d sem roster; usando primeiros PIDs validos do players.dat:"
                % team_id,
                fallback_from_db,
            )
            return fallback_from_db
    except Exception as exc:
        print("[DBV2] roster dinamico falhou; usando fallback:", repr(exc))


    return list(FALLBACK_PLAYER_IDS)




# ======================================================================
# CONFIG
# ======================================================================


def build_config():


    config = {
        "Common": {
            "ClientVersion": 8130,
            "Version": 1,
            "ConfigVersion": 1,
            "TermsOfService": 0,
            "HubLayoutType": 1,
        },
        "Android": {
            "LicenseCheck": False,
            "EmulatorCheck": False,
            "DebuggableCheck": False,
        },
    }


    music = load_music_config()
    if music:
        config["Music"] = music


    return config




# ======================================================================
# TrM.TmP
# ======================================================================


def build_tmp():


    return [


        {


            "PID":
                pid,


            "TID":
                TEAM_ID,


            "ScP":
                False,


            "PDi":
                0,
        }


        for pid in database_player_ids_for_team(TEAM_ID)
    ]




# ======================================================================
# Prf.DrT
#
# Pl:
#   16 jogadores: PID 1..15 + PID 2505 (Rakitic test)
#
# Man.LU:
#   indices dos records em Pl
#
# Man.Ro:
#   cinco indices validos
# ======================================================================


def build_dream_team():


    players = [


        {
            "PID": pid,
        }


        for pid in database_player_ids_for_team(TEAM_ID)
    ]
    lineup = (
        list(range(min(len(players), 40)))
        + [0] * max(0, 40 - min(len(players), 40))
    )


    roles = [
        0,
        1,
        2,
        3,
        4,
    ]


    return {


        "Pl":
            players,


        "Man": {


            "LU":
                lineup,


            "Ro":
                roles,
        },
    }




# ======================================================================
# Prf.Sta
#
# IMPORTANTE:
#
# O nome e "Sta", NAO "sta".
#
#
# ScM:
#   byte[10]
#
#
# Cadeia confirmada:
#
# Prf.Sta.ScM
#       ↓
# FUN_0047d320
#       ↓
# runtime Dream FC
# +0x184 ... +0x1A8
#       ↓
# FUN_00455d98
#       ↓
# temporario
#       ↓
# FUN_002f6df4
#       ↓
# FUN_0040f30c(ScM[i])
#       ↓
# nome .ftm ou NULL
#       ↓
# FUN_004121c0(slot, nome)
#
#
# Tabela FUN_0040f30c:
#
# ID 0   -> corner_a_1_a.ftm
# ...
# ID 100 -> x_surround_a.ftm
#
# IDs 101..255 AUSENTES.
#
#
# Portanto ScM=255:
#
# FUN_0040f30c(255)
#       ↓
# NULL
#       ↓
# FUN_004121c0(slot,NULL)
#       ↓
# usa o default interno daquele slot
# ======================================================================


def build_stadium():


    return {


        "ScM": [


            255,
            255,
            255,
            255,
            255,


            255,
            255,
            255,
            255,
            255,
        ],
    }




# ======================================================================
# ONBOARDING
# ======================================================================


def build_onboarding():


    return {


        "OnbS":
            0,


        "OnbHT":
            0,


        "OnbTD":
            0,


        "PkC":
            False,


        "PkM":
            False,
    }




# ======================================================================
# DEBUG
# ======================================================================


def print_dream_team(drt):


    players = (
        drt["Pl"]
    )


    lineup = (
        drt["Man"]["LU"]
    )


    roles = (
        drt["Man"]["Ro"]
    )


    print(
        "[DLS] DrT:"
    )


    print(
        "[DLS]   Pl quantidade =",
        len(players),
    )


    for i, player in enumerate(
        players
    ):


        print(


            "[DLS]   "
            "Pl[%02d].PID=%d   "
            "LU[%02d]=%d"


            % (


                i,


                player["PID"],


                i,


                lineup[i],
            )
        )


    print(
        "[DLS]   Man.Ro =",
        roles,
    )




def print_stadium(sta):


    print(
        "[DLS] Sta:"
    )


    print(
        "[DLS]   ScM =",
        sta["ScM"],
    )




# ======================================================================
# NEWUSER
# ======================================================================


def handle_newuser(
    flow,
    values,
):


    separator()


    print(
        "[DLS] NEWUSER"
    )


    separator()


    print(
        "[DLS] UId =",
        values.get("UId"),
    )


    print(
        "[DLS] LId =",
        repr(
            values.get("LId")
        ),
    )


    print(
        "[DLS] DBv =",
        values.get("DBv"),
    )


    print(
        "[DLS] ConfigVersion =",
        values.get(
            "ConfigVersion"
        ),
    )


    print(
        "[DLS] ProfileState =",
        values.get(
            "ProfileState"
        ),
    )


    lid = values.get(
        "LId",
        "",
    )


    tmp = (
        build_tmp()
    )


    drt = (
        build_dream_team()
    )


    sta = (
        build_stadium()
    )


    response = {


        "TASK":
            "SUCCESS",


        "UId":
            USER_ID,


        "LId":
            lid,


        "GPa":
            "",


        "PrDBv":
            0,


        "Tok": {


            "TkS":
                "",
        },


        "Sys":
            {},


        "Prf": {


            "Onb":
                build_onboarding(),


            "TrM": {


                "TmP":
                    tmp,
            },


            "DrT":
                drt,


            "Sta":
                sta,
        },


        "Config":
            build_config(),
    }


    inject_full_database(
        response,
        values,
        "NEWUSER",
    )


    print()


    print(
        "[DLS] TmP quantidade =",
        len(tmp),
    )


    print_dream_team(
        drt
    )


    print_stadium(
        sta
    )


    print()


    print(
        "[DLS] RESPOSTA NEWUSER:"
    )


    print(
        pretty(response)
    )


    send_json(
        flow,
        response,
    )


    print()


    print(


        "[DLS] NEWUSER -> "
        "HTTP 200 / "
        "TASK SUCCESS + "
        "CONFIG + TmP + DrT + Sta"
    )


    separator()




# ======================================================================
# SIGNIN
# ======================================================================


def handle_signin(
    flow,
    values,
):


    separator()


    print(
        "[DLS] SIGNIN"
    )


    separator()


    print(
        "[DLS] UId =",
        values.get("UId"),
    )


    print(
        "[DLS] LId =",
        repr(
            values.get("LId")
        ),
    )


    print(
        "[DLS] DBv =",
        values.get("DBv"),
    )


    print(
        "[DLS] ConfigVersion =",
        values.get(
            "ConfigVersion"
        ),
    )


    print(
        "[DLS] ProfileState =",
        values.get(
            "ProfileState"
        ),
    )


    print(
        "[DLS] ProfileStateAfter =",
        values.get(
            "ProfileStateAfter"
        ),
    )


    modifications = (
        values.get(
            "Modifications"
        )
    )


    if modifications is not None:


        print()


        print(
            "[DLS] Modifications "
            "recebidas:"
        )


        print(
            pretty(
                modifications
            )
        )


    lid = values.get(
        "LId",
        "",
    )


    tmp = (
        build_tmp()
    )


    drt = (
        build_dream_team()
    )


    sta = (
        build_stadium()
    )


    # Estado de carreira pronto observado depois do onboarding completo.
    # Em SIGNIN, nao reinicializamos Onb. Se o perfil local ja chegou ao
    # estado pos-onboarding e ainda traz Ini=false, devolvemos um estado
    # de carreira completo com Ini=true para que o menu ja nasca pronto.
    signin_mod_prf = {}
    if isinstance(modifications, dict):
        signin_mod_prf = modifications.get("Prf") or {}


    signin_onb = (
        signin_mod_prf.get("Onb") or {}
        if isinstance(signin_mod_prf, dict)
        else {}
    )
    signin_car = (
        signin_mod_prf.get("Car") or {}
        if isinstance(signin_mod_prf, dict)
        else {}
    )
    signin_mai = (
        signin_car.get("Mai") or {}
        if isinstance(signin_car, dict)
        else {}
    )


    signin_post_onboarding = (
        isinstance(signin_onb, dict)
        and signin_onb.get("OnbS") == 1148
        and signin_onb.get("OnbHT") == 69634
        and signin_onb.get("OnbTD") == 136
    )


    signin_client_ini_false = (
        isinstance(signin_mai, dict)
        and signin_mai.get("Ini") is False
    )


    response = {


        "TASK":
            "SUCCESS",


        "UId":
            USER_ID,


        "LId":
            lid,


        "GPa":
            "",


        "PrDBv":
            0,


        "Tok": {


            "TkS":
                "",
        },


        "Sys":
            {},


        "Prf": {


            # SIGNIN nao deve reinicializar Prf.Onb.
            # NEWUSER cria Onb=0 uma vez; logins seguintes preservam
            # o progresso local do onboarding.
            "TrM": {


                "TmP":
                    tmp,
            },


            "DrT":
                drt,


            "Sta":
                sta,
        },


        "Config":
            build_config(),
    }


    if signin_post_onboarding and signin_client_ini_false:
        signin_mai_ready = build_career_main()
        signin_mai_ready["Ini"] = True
        response["Prf"]["Car"] = {
            "Mai": signin_mai_ready,
        }
        print(
            "[DLS] SIGNIN: POS-ONBOARDING 1148/69634/136 + Ini=false "
            "-> preservando Onb e enviando Car.Mai completo com Ini=true"
        )


    inject_full_database(
        response,
        values,
        "SIGNIN",
    )


    print()


    separator("!")


    print(
        "[DLS] DrT + Sta.ScM"
    )


    separator("!")


    print_dream_team(
        drt
    )


    print_stadium(
        sta
    )


    print()


    print(
        "[DLS] RESPOSTA SIGNIN:"
    )


    print(
        pretty(response)
    )


    send_json(
        flow,
        response,
    )


    print()


    print(


        "[DLS] SIGNIN -> "
        "HTTP 200 / "
        "TASK SUCCESS + "
        "CONFIG + TmP + DrT + Sta"
    )


    separator()




# ======================================================================
# CAREER - ESTADO MINIMO DIAGNOSTICO
#
# Estrutura confirmada no schema de FUN_00476488:
#
#   Car.Mai.Res
#       offset 0x118
#       44 registros
#       stride 0x10
#
#   Car.Mai.TIn.Tou
#       offset 0x3D8
#       4 registros
#       stride 0xE70
#
# Inicio de Tou:
#       +0x000 TID
#       +0x004 Lea
#       +0x005 Rou
#       +0x006 NRo
#       +0x20C Tab
#       +0x714 C
#
# C:
#       +0x00 NT
#       +0x01 NG
#
# FUN_00457524 separa os slots em quatro buckets. Para este teste:
#       Tou[0].TID = 0   -> FUN_0045797c fallback = 1
#       Tou[1].TID = 9   -> FUN_0045797c(9)  = 4
#       Tou[2].TID = 11  -> FUN_0045797c(11) = 0x10
#       Tou[3].TID = 8   -> FUN_0045797c(8)  = 2
#
# Isso preserva a classificacao esperada pelos quatro buckets sem
# inventar TeamIDs externos: qualquer lista de times usa somente 258.
# ======================================================================


CAREER_TOU_TIDS = [
    0,
    9,
    11,
    8,
]




def career_bucket_for_slot(slot):


    # Equivalente pratico da combinacao:
    # FUN_00457448(slot) -> FUN_00457524(slot)


    if slot in (3, 7, 9, 13, 15, 19, 21, 25, 27):
        return 1


    if slot in (5, 11, 17, 23, 28):
        return 2


    if slot in (
        29, 30, 31,
        32, 33, 34,
        35, 36, 37, 38,
        39, 40, 41,
        42, 43,
    ):
        return 3


    return 0




def build_career_results():


    results = []


    for slot in range(44):


        bucket = career_bucket_for_slot(slot)


        results.append({


            # Pla=0: resultado ainda nao jogado.
            "Pla":
                False,


            # O schema confirma arrays de 2 elementos em Tea/Sco/Pen.
            # Usamos somente Dream FC para nunca introduzir TeamID ausente.
            "Tea": [
                TEAM_ID,
                TEAM_ID,
            ],


            "Sco": [
                0,
                0,
            ],


            "Pen": [
                False,
                False,
            ],


            # Mesmo nao jogado, deixamos o TID coerente com o bucket
            # caso algum consumidor leia o campo sem testar Pla primeiro.
            "TID":
                CAREER_TOU_TIDS[bucket],
        })


    return results




def build_career_table():


    # Tabela minima: quatro entradas, todas apontando para o unico
    # TeamID materializado no nosso banco local.
    #
    # NT/NG = 4/1 evita NG=0 e mantem NT/NG inteiro.


    standings = [
        {
            "TID": TEAM_ID,
            "Pla": 0,
            "Win": 0,
            "Los": 0,
            "GoF": 0,
            "GoA": 0,
        }
        for _ in range(4)
    ]


    return {
        "NT": 4,
        "NG": 1,
        "Sta": standings,
    }




def build_career_competition_block():


    # C fica em Tou+0x714.
    # NT e NG sao byte[0] e byte[1] confirmados pelo decompiler.
    # Tea/Sco/Pen sao arrays dinamicos no mesmo bloco.


    return {
        "NT": 4,
        "NG": 1,
        "Tea": [TEAM_ID] * 4,
        "Sco": [0] * 4,
        "Pen": [False] * 4,
    }




def build_career_tournament_info():


    tournaments = []


    for index, tid in enumerate(CAREER_TOU_TIDS):


        tournaments.append({


            "TID":
                tid,


            # Tou[0] e o bucket classificado como 1/fallback, que e o
            # candidato natural a liga principal neste teste.
            "Lea":
                (index == 0),


            "Rou":
                0,


            "NRo":
                1,


            "Tab":
                build_career_table(),


            # Fix e um array dinamico byte[] no schema.
            # Mantemos vazio; NFx continua fornecendo o proximo confronto.
            "Fix":
                [],


            "C":
                build_career_competition_block(),
        })


    return {
        "Tou": tournaments,
    }




def build_career_main():


    return {
        "NFx": {
            "HID": TEAM_ID,
            "AID": TEAM_ID,
            "TID": CAREER_TOU_TIDS[0],
            "Rou": 0,
        },
        "Res": build_career_results(),
        "TIn": build_career_tournament_info(),
    }




def print_career_state(mai):


    print("[DLS] Car.Mai:")
    print("[DLS]   Ini =", mai.get("Ini", "AUSENTE"))
    print("[DLS]   NFx =", pretty(mai["NFx"]))
    print("[DLS]   Res slots =", len(mai["Res"]))


    tou = mai["TIn"]["Tou"]


    print("[DLS]   TIn.Tou quantidade =", len(tou))
    print("[DLS]   Tou TIDs =", [entry["TID"] for entry in tou])


    for i, entry in enumerate(tou):
        print(
            "[DLS]   Tou[%d]: TID=%s Lea=%s Rou=%s NRo=%s "
            "Tab.NT/NG=%s/%s C.NT/NG=%s/%s"
            % (
                i,
                entry["TID"],
                entry["Lea"],
                entry["Rou"],
                entry["NRo"],
                entry["Tab"]["NT"],
                entry["Tab"]["NG"],
                entry["C"]["NT"],
                entry["C"]["NG"],
            )
        )




# ======================================================================
# CAREERINIT
# ======================================================================


def handle_careerinit(
    flow,
    values,
):


    separator()


    print(
        "[DLS] CAREERINIT "
        "INTERCEPTADO"
    )


    separator()


    print()


    print(
        "[DLS] PARAMETROS RECEBIDOS:"
    )


    print(
        "[DLS] MgS =",
        values.get("MgS"),
    )


    print(
        "[DLS] PID =",
        values.get("PID"),
    )


    print(
        "[DLS] TID =",
        values.get("TID"),
    )


    print(
        "[DLS] Cr  =",
        values.get("Cr"),
    )


    print(
        "[DLS] UId =",
        values.get("UId"),
    )


    print(
        "[DLS] DBv =",
        values.get("DBv"),
    )


    print(
        "[DLS] ConfigVersion =",
        values.get(
            "ConfigVersion"
        ),
    )


    print(
        "[DLS] ProfileState =",
        values.get(
            "ProfileState"
        ),
    )


    print(
        "[DLS] ProfileStateAfter =",
        values.get(
            "ProfileStateAfter"
        ),
    )


    modifications = (
        values.get(
            "Modifications"
        )
    )


    if modifications is not None:


        print()


        print(
            "[DLS] Modifications "
            "do CAREERINIT:"
        )


        print(
            pretty(
                modifications
            )
        )


    drt = (
        build_dream_team()
    )


    sta = (
        build_stadium()
    )


    mai = (
        build_career_main()
    )


    # Prf.Car.Mai.Ini e booleano no schema do cliente.
    # GATILHO POS-ONBOARDING (teste estreito):
    # No log atual, depois do fluxo chegar ao menu com Ini=false,
    # os CAREERINIT repetidos vieram sem MgS/PID/TID e com
    # Prf.Onb = {OnbS:1148, OnbHT:69634, OnbTD:136}.
    # Estados anteriores observados usaram outros valores de OnbTD
    # (ex.: 128/129), entao usamos o conjunto completo + Ini=false
    # para evitar ligar Ini durante nome/treinador/capitao.
    mgs = values.get("MgS")
    pid = values.get("PID")
    tid = values.get("TID")


    mod_prf = {}
    if isinstance(modifications, dict):
        mod_prf = modifications.get("Prf") or {}


    mod_onb = mod_prf.get("Onb") or {} if isinstance(mod_prf, dict) else {}
    mod_car = mod_prf.get("Car") or {} if isinstance(mod_prf, dict) else {}
    mod_mai = mod_car.get("Mai") or {} if isinstance(mod_car, dict) else {}


    post_onboarding_state = (
        isinstance(mod_onb, dict)
        and mod_onb.get("OnbS") == 1148
        and mod_onb.get("OnbHT") == 69634
        and mod_onb.get("OnbTD") == 136
    )


    client_ini_false = (
        isinstance(mod_mai, dict)
        and mod_mai.get("Ini") is False
    )


    if (
        mgs is None
        and pid is None
        and tid is None
        and post_onboarding_state
        and client_ini_false
    ):
        mai["Ini"] = True
        print(
            "[DLS] Ini: GATILHO POS-ONBOARDING "
            "None/None/None + Onb=1148/69634/136 + Ini=false "
            "-> enviando boolean true"
        )


    response = {


        "TASK":
            "SUCCESS",


        "UId":
            USER_ID,


        "Tok": {


            "TkS":
                "",
        },


        "Prf": {


            "DrT":
                drt,


            "Sta":
                sta,


            "Car": {


                "Mai":
                    mai,
            },
        },
    }


    print()


    separator("!")


    print(
        "[DLS] CAREERINIT - "
        "NFx + Res + TIn.Tou + DrT + Sta.ScM"
    )


    separator("!")


    print(
        "[DLS] NFx.HID =",
        TEAM_ID,
        "/ 0x%X" % TEAM_ID,
    )


    print(
        "[DLS] NFx.AID =",
        TEAM_ID,
        "/ 0x%X" % TEAM_ID,
    )


    print(
        "[DLS] NFx.TID =",
        mai["NFx"]["TID"],
    )


    print(
        "[DLS] NFx.Rou =",
        mai["NFx"]["Rou"],
    )


    print_career_state(
        mai
    )


    print_dream_team(
        drt
    )


    print_stadium(
        sta
    )


    print()


    print(
        "[DLS] RESPOSTA CAREERINIT:"
    )


    print(
        pretty(response)
    )


    send_json(
        flow,
        response,
    )


    print()


    print(


        "[DLS] CAREERINIT -> "
        "HTTP 200 / "
        "TASK SUCCESS + "
        "NFx + Res + TIn.Tou + DrT + Sta"
    )


    separator("!")




# ======================================================================
# CAREERENDMATCH / OPERACAO 0x0B
#
# FUN_0023c858 precisa de varios campos de Extra.
#
# As tabelas ficam com count=0 neste mock diagnostico.
# ======================================================================


def build_career_endmatch_extra():


    return {


        "UserLeagueInTree":
            0,


        "TournID":
            0,


        "League":
            0,


        "Round":
            0,


        "PrevRoundNumTeams":
            0,


        "PrevRoundNumGroups":
            0,


        "PrevRoundUserGroup":
            0,


        "PrevRoundTeamIDs":
            [],


        "PrevRoundScores":
            [],


        "PrevRoundPens":
            [],


        "CurRoundNumTeams":
            0,


        "CurRoundTeamIDs":
            [],


        "LeagueTableNumTeams":
            0,


        "LeagueTableNumGroups":
            0,


        "LeagueTableTeamIDs":
            [],


        "LeagueTablePlayed":
            [],


        "LeagueTableWin":
            [],


        "LeagueTableLoss":
            [],


        "LeagueTableGoalsFor":
            [],


        "LeagueTableGoalsAgainst":
            [],
    }




def handle_careerendmatch(
    flow,
    values,
):


    separator()


    print(
        "[DLS] CAREERENDMATCH "
        "INTERCEPTADO"
    )


    separator()


    print()


    print(
        "[DLS] RESULTADO DA "
        "PARTIDA RECEBIDO:"
    )


    interesting = (


        "HID",
        "AID",


        "HSc",
        "ASc",


        "HPe",
        "APe",


        "Fft",


        "Apps",


        "PlayerIDs",


        "Energy",
    )


    for key in interesting:


        if key in values:


            print(


                "[DLS] %s = %s"


                % (


                    key,


                    pretty(
                        values.get(key)
                    ),
                )
            )


    modifications = (
        values.get(
            "Modifications"
        )
    )


    if modifications is not None:


        print()


        print(
            "[DLS] Modifications "
            "do CAREERENDMATCH:"
        )


        print(
            pretty(
                modifications
            )
        )


    extra = (
        build_career_endmatch_extra()
    )


    response = {


        "TASK":
            "SUCCESS",


        "UId":
            USER_ID,


        "Tok": {


            "TkS":
                "",
        },


        "Extra":
            extra,
    }


    print()


    separator("!")


    print(
        "[DLS] CAREERENDMATCH / "
        "OP 0x0B"
    )


    print(
        "[DLS] Extra minimo "
        "diagnostico"
    )


    print(
        "[DLS] PrevRoundNumTeams "
        "= 0"
    )


    print(
        "[DLS] CurRoundNumTeams "
        "= 0"
    )


    print(
        "[DLS] LeagueTableNumTeams "
        "= 0"
    )


    print(
        "[DLS] Finish = OMITIDO"
    )


    print(
        "[DLS] Objectives/Injuries/etc "
        "= OMITIDOS"
    )


    separator("!")


    print()


    print(
        "[DLS] RESPOSTA "
        "CAREERENDMATCH:"
    )


    print(
        pretty(response)
    )


    send_json(
        flow,
        response,
    )


    print()


    separator("!")


    print(


        "[DLS] CAREERENDMATCH -> "
        "HTTP 200 / "
        "TASK SUCCESS + Extra"
    )


    separator("!")




# ======================================================================
# OPERACAO FRONTLINE DESCONHECIDA
#
# Continua bloqueada LOCALMENTE.
# ======================================================================


def block_unknown_operation(
    flow,
    operation,
    request_data,
):


    separator("!")


    print(
        "[DLS] NOVA OPERACAO "
        "FRONTLINE DETECTADA"
    )


    separator("!")


    print(
        "[DLS] operation =",
        repr(operation),
    )


    print()


    print(
        "[DLS] REQUEST COMPLETO:"
    )


    print(
        pretty(
            request_data
        )
    )


    print()


    print(
        "[DLS] BLOQUEADA LOCALMENTE."
    )


    print(


        "[DLS] NENHUMA tentativa "
        "sera enviada ao backend antigo."
    )


    separator("!")


    response = {


        "message":
            (
                "Frontline operation blocked "
                "by local DLS21 preservation mock"
            ),


        "operation":
            operation,
    }


    send_json(
        flow,
        response,
        status=503,
    )




# ======================================================================
# MITMPROXY
# ======================================================================


def request(flow):


    host = (
        flow.request.host
        or ""
    ).lower()


    path = (
        flow.request.path
        or ""
    )


    if host != FRONTLINE_HOST:
        return


    if FRONTLINE_PATH not in path:
        return


    print()


    separator("#")


    print(
        "[DLS] FRONTLINE INTERCEPTADO"
    )


    print(
        "[DLS]",
        flow.request.method,
        flow.request.pretty_url,
    )


    separator("#")


    try:


        request_data = (
            decode_request(flow)
        )


    except Exception as exc:


        print()


        print(
            "[DLS] ERRO AO "
            "DECODIFICAR REQUEST:"
        )


        print(
            repr(exc)
        )


        print()


        print(
            "[DLS] BODY ORIGINAL:"
        )


        print(
            flow.request.get_text(
                strict=False
            )
        )


        send_json(
            flow,
            {


                "message":
                    (
                        "Malformed Frontline "
                        "request blocked locally"
                    )
            },
            status=400,
        )


        return


    print()


    print(
        "[DLS] REQUEST INTERNO:"
    )


    print(
        pretty(
            request_data
        )
    )


    if not isinstance(
        request_data,
        dict,
    ):


        print()


        print(
            "[DLS] Request interno "
            "nao e objeto JSON."
        )


        send_json(
            flow,
            {


                "message":
                    (
                        "Invalid Frontline request "
                        "blocked locally"
                    )
            },
            status=400,
        )


        return


    operation = (
        request_data.get(
            "type"
        )
    )


    values = (
        request_data.get(
            "values",
            {},
        )
    )


    if not isinstance(
        values,
        dict,
    ):


        values = {}


    print()


    print(
        "[DLS] operation =",
        repr(operation),
    )


    # --------------------------------------------------------------
    # SAFE SHADOW PROBE
    #
    # Consulta o backend real com uma COPIA da request, mas nao deixa
    # nenhuma resposta real chegar ao jogo. Depois disso, o fluxo segue
    # normalmente para os handlers locais abaixo.
    # --------------------------------------------------------------


    _start_shadow_probe_async(
        flow,
        request_data,
        operation,
    )




    # --------------------------------------------------------------
    # NEWUSER
    # --------------------------------------------------------------


    if operation == "NEWUSER":


        handle_newuser(
            flow,
            values,
        )


        return




    # --------------------------------------------------------------
    # SIGNIN
    # --------------------------------------------------------------


    if operation == "SIGNIN":


        handle_signin(
            flow,
            values,
        )


        return




    # --------------------------------------------------------------
    # CAREERINIT / 0x0A
    # --------------------------------------------------------------


    if operation == "CAREERINIT":


        handle_careerinit(
            flow,
            values,
        )


        return




    # --------------------------------------------------------------
    # CAREERENDMATCH / 0x0B
    # --------------------------------------------------------------


    if operation == "CAREERENDMATCH":


        handle_careerendmatch(
            flow,
            values,
        )


        return




    # --------------------------------------------------------------
    # QUALQUER OUTRA OPERACAO:
    #
    # NUNCA deixa sair para o backend antigo.
    # --------------------------------------------------------------


    block_unknown_operation(
        flow,
        operation,
        request_data,
    )




# ======================================================================
# STARTUP
# ======================================================================


separator()


print(
    "DLS21 8.13 - LAB V2 / CONTROL MOCK"
)


print(


    "NEWUSER + SIGNIN + CONFIG + "
    "TmP + DrT + Sta.ScM + "
    "CAREERINIT + NFx + Res + TIn.Tou + "
    "CAREERENDMATCH + DBv/DBt/DBp/DBl + Music"
)


separator()


print()


print(
    "ESTADO:"
)


print(


    "  DrT.Pl        = "
    "dinamico: teamplayerlinks.dat (fallback 18 records)"
)


print(


    "  DrT.Man.LU    = "
    "dinamico + preenchimento ate 40"
)


print(


    "  DrT.Man.Ro    = "
    "indices 0..4"
)


print(


    "  Sta.ScM       = "
    "[255] * 10"
)


print(


    "  IDs .ftm      = "
    "0..100"
)


print(


    "  ID 255 .ftm   = "
    "AUSENTE"
)


print(


    "  NFx.HID/AID   = "
    "258 / 0x102"
)


print(


    "  Car.Mai.Res   = "
    "44 slots"
)


print(


    "  TIn.Tou       = "
    "4 records / TIDs [0, 9, 11, 8]"
)


print(


    "  CAREERENDMATCH = "
    "HTTP 200 + Extra minimo"
)


print()


print(
    "TESTE ATUAL:"
)


print(


    "  Prf.Sta.ScM usa S MAIUSCULO."
)


print(


    "  ScM=255 deve fazer "
    "FUN_0040f30c retornar NULL."
)


print(


    "  FUN_004121c0 deve entao "
    "usar o default interno "
    "de cada slot."
)


print()


print(
    "SEGURANCA DO LAB:"
)


print(


    "  Operacoes Frontline desconhecidas "
    "continuam BLOQUEADAS LOCALMENTE."
)


print(


    "  Sem fallback para o backend antigo."
)


print()


print(
    "SAFE SHADOW PROBE:"
)


print(
    "  ativo          =",
    SHADOW_REAL_BACKEND,
)


print(
    "  operacoes      =",
    sorted(SHADOW_OPERATIONS),
)


print(
    "  max por op     =",
    SHADOW_MAX_PER_OPERATION,
)


print(
    "  forca DBv=0    =",
    SHADOW_FORCE_DBV_ZERO,
)


print(
    "  captura em     =",
    SHADOW_CAPTURE_DIR,
)


print(
    "  resposta real  = NUNCA enviada ao DLS"
)


print()


print(
    "LAB V2 DATABASE:"
)


if not ENABLE_LOCAL_DATABASE_INJECTION:
    print("  injecao local = DESATIVADA POR CODIGO")
    print("  DBv/DBt/DBp/DBl = NUNCA enviados pelo mock")
    print("  arquivos do PC   = IGNORADOS")
else:
    _v2_db = load_full_database()
    if _v2_db:
        print("  DBv           =", _v2_db["version"])
        print("  pasta         =", _v2_db["dir"])
        print("  full DB       = PRONTA")
    else:
        print("  full DB       = DESATIVADA/AUSENTE")


print()


_startup_music = load_music_config()
print()
print("MUSIC:")
if _startup_music:
    print("  TrackCount      =", _startup_music.get("TrackCount"))
    print("  InitialBootTrack=", _startup_music.get("InitialBootTrack"))
    print("  FileName[0:5]   =", _startup_music.get("FileName", [])[:5])
else:
    print("  Config.Music    = AUSENTE (fallback interno da engine)")
print()
print(
    "Esperando requests..."
)


print()