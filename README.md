# DNS клиент
Автор: Пироговский Леонид

## Описание
DNS клиент для преобразования адреса в IP адрес.

## Состав
* Клиент: dnsclient.py
* Тесты: test_dnsclient.py

## Использование
main.py \[-h] \[-r] \[-6] \[-s адрес] \[-a] \[-d] \[-t] \[-m таймаут] имя_хоста

*  имя_хоста - адрес, который необходимо преобразовать
*  -h - отобразить помощь
*  -r - отключение рекурсивных запросов, поддерживается не всеми серверами.
*  -6 - искать IPv6 адрес вместо IPv4
*  -p порт - использовать указанный порт для связи с DNS сервером
*  -s адрес - использовать сервер DNS по указанному адресу
*  -a - показывать, получен ли ответ от доверенных серверов
*  -d - при отсылке или приеме сообщения его hex-дамп будет отображен в консоли вместе с IP получателя
*  -t - будет использоваться протокол TCP Вместо UDP
*  -m таймаут - указывание собственного времени ожидания ответа в секундах
