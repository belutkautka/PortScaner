Утилита для сканирования TCP и UDP портов

Состав:
    -Исполняемый файл: portscan.py
    -Сканеры: scaner.py
Справка по командам: python portscan.py {-h|--help}
Запуск утилиты: python portscan.py [OPTIONS] IP_ADDRESS [{tcp|udp}/[PORT|PORT-PORT],...]
Реализованно:
    -UDP-сканирование
    -TCP-сканирование, варианты:
        TCP SYN с формированием пакетов с использованием scapy
        полная установка соединения TCP (создаётся сокет и далее .connect)
    - Распараллеливание: select/poll/epoll
    - Подробный режим
    - Определение протокола