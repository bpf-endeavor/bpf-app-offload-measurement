def get_val(line):
    t = line.strip().split()[0]
    t = t.replace(',', '')
    t = int(t)
    return t

def parse(f):
    data = {}
    tmp = {}
    looking = True
    for line in f:
        if line.startswith('-- zipf'):
            tmp = {}
            flows = float(line.split(':')[1].strip())
            tmp['flows'] = flows
            looking=False
        if looking:
            continue
        elif 'tput' in line:
            tmp['throughput'] = float(line.strip().split()[1])
        elif 'instructions' in line:
            tmp['instructions'] = get_val(line)
        elif 'L1-dcache-loads' in line:
            tmp['l1-load'] = get_val(line)
        elif 'L1-dcache-load-misses' in line:
            tmp['l1-miss'] = get_val(line)
        elif 'l2_rqsts.demand_data_rd_miss' in line:
            tmp['l2-miss'] = get_val(line)
        elif 'LLC-load-misses' in line:
            tmp['llc-miss'] = get_val(line)
        elif 'seconds time elapsed' in line:
            data[tmp['flows']] = tmp
            looking = True
    return data

def report(file_path, data, bsline):
    bs_l1_miss = bsline['l1-miss']
    bs_l1_load = bsline['l1-load']
    bs_tput = bsline['throughput'] * 1000000
    bs_l1_miss_per_packet = bs_l1_miss / bs_tput

    keys = list(data.keys())
    keys.sort()
    print('--------------------')
    print(file_path)
    for flows in keys:
        tmp = data[flows]
        instructions = tmp['instructions']
        # all_cache_misses = tmp['l1-miss'] # + tmp['l2-miss'] + tmp['llc-miss']
        l1_miss = tmp['l1-miss']
        l1_load = tmp['l1-load']
        tput = tmp['throughput'] * 1000000
        l1_miss_per_packet = l1_miss / tput

        # dinom = l1_load / bs_l1_load
        # nom = l1_miss / bs_l1_miss
        # n = round(nom / dinom, ndigits=2)

        n = round(l1_miss_per_packet / bs_l1_miss_per_packet, ndigits=2)
        print(f'{flows}: {n}')

def main():
    with open('baseline.txt', 'r') as fd:
        baseline_data = parse(fd)[0]

    files = ['array.txt', 'hash.txt', 'lru_hash.txt']
    for f in files:
        with open(f, 'r') as fd:
            data = parse(fd)
        report(f, data, baseline_data)


if __name__ == '__main__':
    main()
