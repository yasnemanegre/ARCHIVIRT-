-- Snort 3 configuration for ARCHIVIRT (IaC)
-- Deployed automatically by Ansible

output_timestamps = { utc = true }

runmode = 'pcap-mode'

pcap = {
    interface = 'ens4',
    snaplen = 65535,
    promiscuous = true,
}

alert_fast = {
    file = true,
    limit = 100000,
}

alert_json = {
    file = true,
    limit = 100000,
}

-- Utilisation du chemin absolu pour éviter toute ambiguïté
ips = {
    include = '/etc/snort3/rules/archivirt.rules'
}
