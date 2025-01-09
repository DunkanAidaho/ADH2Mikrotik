import json
import logging
import os
import time
from datetime import datetime, timedelta
from base64 import b64decode
import struct
from routeros_api import RouterOsApiPool
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Настройки
ROUTER_IP = "..."
USERNAME = "..."
PASSWORD = "..."
LOG_FILE_PATH = '' # Ваш путь к логу запросов AdguardHome '/usr/local/AdGuardHome/data/querylog.json'
INTERFACE = '...'
ROUTE_DISTANCE = "20"  # Приведено к строковому формату
ROUTE_SCOPE = "40"     # Приведено к строковому формату
ROUTE_TARGET_SCOPE = "30"  # Приведено к строковому формату
DOMAINS = [
    "youtube.com", "youtube.ru", "ytimg.com", "withyoutube.com", "youtu.be",
    "youtube-nocookie.com", "yt.be", "youtubemobilesupport.com", "youtubekids.com",
    "youtubego.com", "youtubegaming.com", "youtubefanfest.com", "youtubeeducation.com",
    "ggpht.com", "googlevideo.com", "youtube.googleapis.com", "youtubeembeddedplayer.googleapis.com",
    "youtubei.googleapis.com", "youtube-ui.l.google.com", "wide-youtube.l.google.com"
] 

# Настройки логирования
LOG_TO_CONSOLE = False
LOG_TO_FILE = True
LOG_FILE_NAME = "/var/log/script.log"  # Путь к файлу лога

# Настройка логирования
logger = logging.getLogger('main')
logger.setLevel(logging.DEBUG)

if LOG_TO_CONSOLE:
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

if LOG_TO_FILE:
    file_handler = logging.FileHandler(LOG_FILE_NAME)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

# Переменные состояния
routes_state = {}  # {IP: {'domain': str, 'timestamp': datetime}}


def connect_to_mikrotik():
    """Подключение к Mikrotik через API."""
    try:
        api_pool = RouterOsApiPool(ROUTER_IP, username=USERNAME, password=PASSWORD, plaintext_login=True)
        api = api_pool.get_api()
        logger.info("Успешное подключение к Mikrotik")
        return api, api_pool
    except Exception as e:
        logger.error(f"Ошибка подключения к Mikrotik: {e}")
        raise


def add_route_to_mikrotik(api, ip, domain):
    """Добавление маршрута в Mikrotik."""
    if ip == "0.0.0.0":
        logger.warning(f"Пропущено добавление маршрута для {ip} (домен: {domain})")
        return  # Не добавляем маршрут для 0.0.0.0
    try:
        api.get_resource('/ip/route').add(
            dst_address=f"{ip}/32",
            gateway=INTERFACE,
            distance=ROUTE_DISTANCE,
            scope=ROUTE_SCOPE,
            target_scope=ROUTE_TARGET_SCOPE,
            comment=f"Added by script for domain {domain}"
        )
        logger.info(f"Маршрут для {ip} (домен: {domain}) добавлен")
    except Exception as e:
        logger.error(f"Ошибка добавления маршрута для {ip}: {e}")


def remove_route_from_mikrotik(api, ip):
    """Удаление маршрута из Mikrotik."""
    try:
        route_id = api.get_resource('/ip/route').get(dst_address=f"{ip}/32")[0]['.id']
        api.get_resource('/ip/route').remove(id=route_id)
        logger.info(f"Маршрут для {ip} удален")
    except Exception as e:
        logger.error(f"Ошибка удаления маршрута для {ip}: {e}")


def parse_dns_response(data):
    """Парсинг DNS-ответа из закодированных данных Base64."""
    try:
        decoded_data = b64decode(data)
        offset = 12  # Пропускаем заголовок DNS-запроса

        # Пропускаем вопросы
        qdcount = struct.unpack('!H', decoded_data[4:6])[0]
        for _ in range(qdcount):
            while decoded_data[offset] != 0:
                offset += 1
            offset += 5  # Пропускаем NULL-байт и QTYPE/QCLASS
         # Парсим ответы
        ancount = struct.unpack('!H', decoded_data[6:8])[0]
        for _ in range(ancount):
            offset += 2  # Пропускаем имя (указатель)
            rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', decoded_data[offset:offset+10])
            offset += 10
            rdata = decoded_data[offset:offset+rdlength]
            offset += rdlength

            if rtype == 1:  # A-запись (IPv4)
                ip = ".".join(map(str, rdata))
                return ip
    except Exception as e:
        logger.error(f"Ошибка парсинга DNS-ответа: {e}")
    return None


def process_log_file(api):
    """Обработка файла логов и управление маршрутами."""
    global routes_state

    now = datetime.now()

    # Проверяем устаревшие маршруты
    for ip in list(routes_state.keys()):
        if now - routes_state[ip]['timestamp'] > timedelta(days=3):
            remove_route_from_mikrotik(api, ip)
            del routes_state[ip]
            logger.info(f"Удален устаревший маршрут для IP {ip}")

    # Читаем файл логов построчно
    if not os.path.exists(LOG_FILE_PATH):
        logger.error(f"Файл логов {LOG_FILE_PATH} не найден!")
        return

    with open(LOG_FILE_PATH, 'r') as f:
        for line in f:
            try:
                log_entry = json.loads(line.strip())  # Парсим каждую строку как отдельный JSON-объект
                domain = log_entry.get('QH', '')
                encoded_answer = log_entry.get('Answer', '')
                ip = parse_dns_response(encoded_answer) if encoded_answer else log_entry.get('IP', '')

                if not domain or not ip:
                    continue

                if any(d in domain for d in DOMAINS):
                    if ip not in routes_state:
                        add_route_to_mikrotik(api, ip, domain)
                        routes_state[ip] = {'domain': domain, 'timestamp': now}
                        logger.info(f"Добавлен маршрут для IP {ip} (домен: {domain})")
            except json.JSONDecodeError as e:
                logger.error(f"Ошибка декодирования JSON в строке: {line.strip()} - {e}")


class LogFileEventHandler(FileSystemEventHandler):
    """Обработчик событий изменения файла."""

    def __init__(self, api):
        self.api = api

    def on_modified(self, event):
        if event.src_path == LOG_FILE_PATH:
            logger.info(f"Файл логов изменен: {event.src_path}")
            process_log_file(self.api)


def main():
    """Основная функция."""
    api, api_pool = connect_to_mikrotik()
    
    try:
        event_handler = LogFileEventHandler(api)
        observer = Observer()
        observer.schedule(event_handler, path=os.path.dirname(LOG_FILE_PATH), recursive=False)
        observer.start()

        logger.info("Скрипт запущен. Ожидание изменений файла логов...")
        
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        observer.stop()
    
    observer.join()
    api_pool.disconnect()


if __name__ == "__main__":
    main()
