import argparse
from concurrent.futures.thread import ThreadPoolExecutor

from scaner import scaner
def input_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip', type=str, help='ip сервера, к которму нужно подключиться')
    parser.add_argument('ports', type=str,nargs='+', help='Порты в формате [{tcp|udp}/[PORT|PORT-PORT],...]')
    parser.add_argument('--timeout', type=float, help='Время ожидания ответа от порта в секундах', default=2)
    parser.add_argument('-j','--num-threads', type=int, help='Число потоков', default=1)
    parser.add_argument('-v', '--verbose', action='store_true', help='Подробный режим')
    parser.add_argument('-g', '--guess', action='store_true', help='Определение протокола прикладного уровня')
    args = parser.parse_args()
    return args


def processing_input(ports):
    name_arr = []
    num_arr = []
    for port in ports:
        split_port = port.split("/")
        if len(split_port) == 1:
            continue
        name_arr.append(split_port[0])
        num_port = split_port[1].split(",")
        pre_arr = []
        for ind in num_port:
            pre_arr.append(ind.split("-"))
        num_arr.append(pre_arr)
    return name_arr, num_arr


def main():
    pars = input_argument()
    timeout = pars.timeout
    threads_count=pars.num_threads
    ip = pars.ip
    ports = pars.ports
    names, nums = processing_input(ports)
    temp = 0
    with ThreadPoolExecutor(max_workers=threads_count) as executor:
        for num in nums:
            name = names[temp]
            for port in num:
                start, end = 0, 0
                if len(port) == 1:
                    start, end = int(port[0]), int(port[0])+1
                elif len(port) == 2:
                    start, end = int(port[0]), int(port[1])+1
                for i in range(start, end):
                    if name == "tcp":
                        executor.submit(scaner.scan_tcp_port,ip,i,timeout,pars.verbose,pars.guess)
                    elif name == "udp":
                        executor.submit(scaner.scan_udp_port, ip, i, timeout, pars.verbose, pars.guess)
            temp += 1


if __name__ == '__main__':
    main()
