# ADH2Mikrotik
Скрипт, берет обращения к доменам указанным в переменной domains, и добавляет соответствующий маршрут в Mikrotik.

Требования:
- устройство с ROS
- Adguardhome на linux сервере
- querylog в ADG enabled: true, file_enabled: true  в конфиге AdGuardHome.yaml
- учетная запись в Mikrotik с доступом к api на запись.
- Python3 на сервере с соответствующими модулями (по установке модулей для своего дистрибутива, вопросы необходимо адресовать в тематические форумы)


ROUTER_IP = "..." - IP адрес вашего устройства Mikrotik 
USERNAME = "..." - учетная запись api mikrotik
PASSWORD = "..." - пароль от учетной записи
LOG_FILE_PATH = '' # Ваш путь к логу запросов AdguardHome, в моем случае '/usr/local/AdGuardHome/data/querylog.json'
INTERFACE = '...' - VPN интерфейс mikrotik, который "смотрит" в VPN
ROUTE_DISTANCE = "20" - параметр маршрута в mikrotik
ROUTE_SCOPE = "40" - параметр маршрута в mikrotik
ROUTE_TARGET_SCOPE = "30" - параметр маршрута в mikrotik
DOMAINS = [] - домены, IP адреса которых, требуется завернуть в VPN Пример: 
*/ DOMAINS = [
    "youtube.com", "youtube.ru", "ytimg.com", "withyoutube.com", "youtu.be",
    "youtube-nocookie.com", "yt.be", "youtubemobilesupport.com", "youtubekids.com",
    "youtubego.com", "youtubegaming.com", "youtubefanfest.com", "youtubeeducation.com",
    "ggpht.com", "googlevideo.com", "youtube.googleapis.com", "youtubeembeddedplayer.googleapis.com",
    "youtubei.googleapis.com", "youtube-ui.l.google.com", "wide-youtube.l.google.com"
]  */

# Настройки логирования
LOG_TO_CONSOLE = False # логирование в консоль
LOG_TO_FILE = True #логирование в файл
LOG_FILE_NAME = "/var/log/script.log"  # Путь к файлу лога


Плюсы:
+ не нужно BGP
+ в VPN пробрасываются только те домены которые указаны, без лишних хвостов
+ не нужно думать о ASN ютуба и прочих сервисов. т.к. маршрут добавляется только к тому адресу, адрес которого отрезолвил
+ скрипт сам чистит маршруты (старше N дней)

Минусы:
- скрипт писался не профессионалом при помощи ChatGPT
- скрипт не учитывает версионирование ADH и Mikrotik
- скрипт не учитывает VPN без интерфейса(ikev2\ipsec)
