# SCRIPT_VERSION: 3.8
import requests
import json
import sys
import re
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
CONFIG_FILE = SCRIPT_DIR / "config.json"
TOKEN_CACHE_FILE = SCRIPT_DIR / "token_cache.json"

AUTH_URL = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"
BASE_DNS_API_URL = "https://api.selectel.ru/domains/v2"

def load_config():
    if not CONFIG_FILE.exists():
        print(f"❌ Файл '{CONFIG_FILE}' не найден.")
        sys.exit(1)
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    return {k: str(v).strip() if isinstance(v, str) else v for k, v in cfg.items()}

def get_valid_token(config):
    headers = {"Content-Type": "application/json"}
    if TOKEN_CACHE_FILE.exists():
        try:
            with open(TOKEN_CACHE_FILE, 'r', encoding='utf-8') as f:
                token = json.load(f).get("token")
            if requests.get(f"{BASE_DNS_API_URL}/zones?limit=1", headers={"X-Auth-Token": token}, timeout=5).status_code == 200:
                return token
        except Exception:
            pass

    print("🔄 Получение токена авторизации...")
    payload = {
        "auth": {
            "identity": {"methods": ["password"], "password": {"user": {"name": config["username"], "domain": {"name": config["account_id"]}, "password": config["password"]}}},
            "scope": {"project": {"name": config["project_name"], "domain": {"name": config["account_id"]}}}
        }
    }
    try:
        resp = requests.post(AUTH_URL, json=payload, headers=headers, timeout=10)
        if resp.status_code == 201:
            token = resp.headers.get("X-Subject-Token")
            print(f"✅ Авторизация успешна! Токен: {token[:20]}...")
            with open(TOKEN_CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump({"token": token}, f)
            return token
        print(f"❌ Ошибка авторизации: {resp.status_code} {resp.text}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"❌ Сетевая ошибка: {e}")
        return None

def remove_comment(line):
    """Удаляет комментарии (;), игнорируя точки с запятой внутри двойных кавычек."""
    in_quotes = False
    result = []
    for char in line:
        if char == '"':
            in_quotes = not in_quotes
        if char == ';' and not in_quotes:
            break
        result.append(char)
    return "".join(result).strip()

def parse_zone_file(filepath):
    zone_name = Path(filepath).name
    records_dict = {}
    default_ttl = 3600
    current_origin = zone_name + "." # Значение по умолчанию
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        
    lines = [remove_comment(line) for line in content.split('\n')]
    
    # 1. Обработка директив $ORIGIN и $TTL
    processed_lines = []
    for line in lines:
        upper_line = line.upper().strip()
        if upper_line.startswith('$ORIGIN'):
            parts = line.split()
            if len(parts) >= 2:
                current_origin = parts[1]
                if not current_origin.endswith('.'):
                    current_origin += '.'
            continue
        elif upper_line.startswith('$TTL'):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    default_ttl = int(parts[1])
                except ValueError:
                    pass
            continue
        elif upper_line.startswith('$'):
            continue # Игнорируем другие директивы ($INCLUDE и т.д.)
            
        processed_lines.append(line)
        
    # 2. Объединение многострочных записей
    joined_lines, current_line = [], ""
    for line in processed_lines:
        if '(' in line and ')' not in line:
            current_line += line + " "
        elif current_line:
            current_line += line + " "
            if ')' in line:
                joined_lines.append(current_line.strip())
                current_line = ""
        else:
            joined_lines.append(line)
            
    last_name = "@"
    for line in joined_lines:
        tokens = line.split()
        if not tokens or any(t.upper() in ['SOA', 'NS'] for t in tokens):
            continue
            
        idx, name, ttl, rec_type = 0, last_name, default_ttl, ""
        while idx < len(tokens):
            t = tokens[idx]
            if t.upper() in ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'CAA', 'PTR']:
                rec_type, idx = t.upper(), idx + 1
                break
            elif t.isdigit():
                ttl, idx = int(t), idx + 1
            elif t.upper() in ['IN', 'CH', 'HS']:
                idx += 1
            else:
                name, last_name, idx = t, t, idx + 1
                
        if rec_type:
            content_val = " ".join(tokens[idx:])
            
            # 3. Очистка круглых скобок BIND (они нужны только для переноса строк)
            content_val = re.sub(r'\s*\(\s*', ' ', content_val)
            content_val = re.sub(r'\s*\)\s*', ' ', content_val)
            content_val = " ".join(content_val.split()) # Нормализация пробелов
            
            # 4. Формирование полного имени записи (FQDN)
            if name == "@":
                api_name = current_origin
            elif name.endswith("."):
                api_name = name
            else:
                api_name = f"{name}.{current_origin}"
                
            # 5. Специфичная обработка типов записей
            if rec_type == 'CNAME':
                if content_val == "@":
                    content_val = current_origin
                elif not content_val.endswith("."):
                    content_val = f"{content_val}.{current_origin}"
                    
            if rec_type == 'MX':
                parts = content_val.split(maxsplit=1)
                if len(parts) == 2:
                    priority, target = parts
                    if target == "@":
                        target = current_origin
                    elif not target.endswith("."):
                        target = f"{target}.{current_origin}"
                    content_val = f"{priority} {target}"
                    
            if rec_type == 'SRV':
                parts = content_val.split()
                if len(parts) == 4:
                    priority, weight, port, target = parts
                    if target == "@":
                        target = current_origin
                    elif not target.endswith("."):
                        target = f"{target}.{current_origin}"
                    content_val = f"{priority} {weight} {port} {target}"
            
            # ИСПРАВЛЕНО: Автоматическое добавление кавычек для TXT записей, если их нет
            if rec_type == 'TXT':
                content_val = content_val.strip()
                if not content_val.startswith('"'):
                    content_val = f'"{content_val}"'
                elif not content_val.endswith('"'):
                    # На случай опечатки в BIND-файле (начинается с ", но не заканчивается)
                    content_val = f'{content_val}"'
            
            key = (api_name, rec_type)
            if key not in records_dict:
                records_dict[key] = {"ttl": ttl, "contents": []}
            
            if content_val not in records_dict[key]["contents"]:
                records_dict[key]["contents"].append(content_val)

    records = []
    for (name, rtype), data in records_dict.items():
        records.append({"name": name, "type": rtype, "ttl": data["ttl"], "contents": data["contents"]})
        
    return zone_name, records

def get_existing_rrsets(zone_id, token):
    headers = {"X-Auth-Token": token}
    resp = requests.get(f"{BASE_DNS_API_URL}/zones/{zone_id}/rrset", headers=headers)
    if resp.status_code == 200:
        rrsets = {}
        for item in resp.json().get("result", []):
            key = (item["name"], item["type"])
            rrsets[key] = {
                "id": item["id"],
                "ttl": item["ttl"],
                "contents": [r["content"] for r in item["records"] if not r.get("disabled")]
            }
        return rrsets
    return {}

def get_or_create_zone(zone_name, token):
    headers = {"X-Auth-Token": token, "Content-Type": "application/json"}
    api_zone_name = zone_name if zone_name.endswith('.') else zone_name + '.'
    resp = requests.post(f"{BASE_DNS_API_URL}/zones", json={"name": api_zone_name}, headers=headers)
    if resp.status_code in [200, 201]:
        return resp.json()["id"], True
    if resp.status_code == 409:
        for z in requests.get(f"{BASE_DNS_API_URL}/zones", headers=headers, params={"filter": api_zone_name}).json().get("result", []):
            if z["name"] == api_zone_name:
                return z["id"], False
    print(f"   ❌ Ошибка зоны: {resp.status_code} {resp.text}")
    return None, False

def process_zone_file(filepath, token, config):
    print(f"\n{'='*50}\n📂 Обработка: {filepath}")
    zone_name, records = parse_zone_file(filepath)
    print(f"   📝 Найдено уникальных RRSet-ов: {len(records)}")
    if not records:
        return 0, 0, 0

    zone_id, is_new = get_or_create_zone(zone_name, token)
    if not zone_id:
        return 0, 0, len(records)
    print(f"   ✅ Зона '{zone_name}' {'создана' if is_new else 'уже существовала'} (ID: {zone_id})")

    existing = get_existing_rrsets(zone_id, token)
    success, errors, skipped = 0, 0, 0
    headers = {"X-Auth-Token": token, "Content-Type": "application/json"}
    overwrite = config.get("overwrite_existing", False)

    for rec in records:
        key = (rec["name"], rec["type"])
        parsed_contents = set(rec["contents"])
        
        if key in existing:
            ex = existing[key]
            existing_contents = set(ex["contents"])
            
            if parsed_contents == existing_contents and rec["ttl"] == ex["ttl"]:
                contents_str = ", ".join(rec["contents"])
                print(f"   ℹ️  {rec['type']:5} {rec['name']:<35} -> {contents_str} (совпадает)")
                success += 1
                continue
            
            if overwrite:
                contents_str = ", ".join(rec["contents"])
                print(f"   🔄 {rec['type']:5} {rec['name']:<35} -> {contents_str} (замена)")
                patch_payload = {
                    "ttl": rec["ttl"], 
                    "records": [{"content": c, "disabled": False} for c in rec["contents"]]
                }
                patch_resp = requests.patch(f"{BASE_DNS_API_URL}/zones/{zone_id}/rrset/{ex['id']}", json=patch_payload, headers=headers)
                if patch_resp.status_code in [200, 204]:
                    print(f"      ✅ Успешно обновлено")
                    success += 1
                else:
                    print(f"      ❌ Ошибка обновления: {patch_resp.status_code} {patch_resp.text}")
                    errors += 1
            else:
                contents_str = ", ".join(rec["contents"])
                ex_str = ", ".join(ex["contents"])
                print(f"   ⚠️  {rec['type']:5} {rec['name']:<35} -> {contents_str} (пропущено, в Selectel: {ex_str})")
                skipped += 1
        else:
            contents_str = ", ".join(rec["contents"])
            print(f"   ✅ {rec['type']:5} {rec['name']:<35} -> {contents_str} (создание...)")
            payload = {
                "name": rec["name"], 
                "ttl": rec["ttl"], 
                "type": rec["type"], 
                "records": [{"content": c, "disabled": False} for c in rec["contents"]]
            }
            resp = requests.post(f"{BASE_DNS_API_URL}/zones/{zone_id}/rrset", json=payload, headers=headers)
            
            if resp.status_code in [200, 201]:
                print(f"      ✅ Успешно создано")
                success += 1
            elif resp.status_code == 422 and "Conflicts with pre-existing RRset" in resp.text:
                print(f"      ℹ️  (уже существует в Selectel, пропущено)")
                skipped += 1
            else:
                print(f"      ❌ Ошибка создания: {resp.status_code} {resp.text}")
                errors += 1

    print(f"   📊 Итог: Создано/совпало: {success}, Пропущено: {skipped}, Ошибок: {errors}")
    return success, errors, skipped

def main():
    if len(sys.argv) < 2:
        print("Использование: python selectel_dns.py <путь_к_файлу_или_папке>")
        sys.exit(1)
    target_path = Path(sys.argv[1])
    if not target_path.exists():
        print(f"❌ Путь '{target_path}' не найден.")
        sys.exit(1)

    config = load_config()
    token = get_valid_token(config)
    if not token:
        sys.exit(1)

    files = [f for f in target_path.iterdir() if f.is_file() and not f.name.startswith('.')] if target_path.is_dir() else [target_path]
    total_success, total_errors, total_skipped = 0, 0, 0
    
    for f in files:
        s, e, sk = process_zone_file(str(f), token, config)
        total_success += s
        total_errors += e
        total_skipped += sk

    print(f"\n{'='*50}\n🎉 ОБЩИЙ ИТОГ: Файлов: {len(files)}, Успешно: {total_success}, Пропущено: {total_skipped}, Ошибок: {total_errors}")

if __name__ == "__main__":
    main()
