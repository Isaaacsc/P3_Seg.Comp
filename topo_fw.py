import os
import time
from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink


PHYSICAL_IF = "wlp0s20f3"
VETH_HOST_IP = "192.168.5.100/24"
VETH_HOST_ADDR = "192.168.5.100"
VETH_MININET_NAME = "veth-mininet"
VETH_HOST_NAME = "veth-host"
MININET_EXTERNAL_NET = "192.168.5.0/24"
MININET_INTERNAL_NET = "10.0.0.0/28"

def setup_network():
    """Configura a topologia completa da rede com firewall"""
    info('*** Limpando ambiente anterior\n')
    os.system('mn -c > /dev/null 2>&1')

    # Criar rede
    net = Mininet(controller=Controller, switch=OVSKernelSwitch, link=TCLink)
    
    # Controlador
    net.addController('c0')
    
    # Switches
    internal_switch = net.addSwitch('s1')
    external_switch = net.addSwitch('s2')
    
    # Hosts da rede interna (10.0.0.0/28) - USAM FIREWALL COMO GATEWAY
    internal_hosts = [
        net.addHost('h1', ip='10.0.0.2/28', defaultRoute='via 10.0.0.1'),
        net.addHost('h2', ip='10.0.0.3/28', defaultRoute='via 10.0.0.1'),
        net.addHost('h3', ip='10.0.0.4/28', defaultRoute='via 10.0.0.1'),
        net.addHost('h4', ip='10.0.0.5/28', defaultRoute='via 10.0.0.1')
    ]
    
    # Firewall
    firewall = net.addHost('fw', ip=None)
    
    # Hosts da rede externa - USAM HOST FÍSICO COMO GATEWAY
    external_hosts = [
        net.addHost('h5', ip='192.168.5.10/24', defaultRoute='via 192.168.5.100'),
        net.addHost('h6', ip='192.168.5.20/24', defaultRoute='via 192.168.5.100')
    ]
    
    # Conexões físicas
    info('*** Criando conexões de rede\n')
    
    # Rede interna: hosts -> switch interno
    for host in internal_hosts:
        net.addLink(host, internal_switch)
    
    # Firewall conectado a ambas as redes
    net.addLink(firewall, internal_switch)  # Interface interna
    net.addLink(firewall, external_switch)  # Interface externa
    
    # Rede externa: hosts -> switch externo  
    for host in external_hosts:
        net.addLink(host, external_switch)
    
    # Iniciar rede
    info('*** Iniciando rede\n')
    net.start()
    
    # Configurar interfaces do firewall
    info('*** Configurando interfaces do firewall\n')
    firewall.cmd('ifconfig fw-eth0 10.0.0.1/28 up')  # Interface interna
    firewall.cmd('ifconfig fw-eth1 192.168.5.1/24 up')  # Interface externa
    firewall.cmd('ifconfig lo 127.0.0.1 up')
    
    # Conectar à internet real
    connect_to_internet(net, external_switch)
    
    # Configurar DNS COM ARQUIVOS TEMPORÁRIOS
    setup_dns(internal_hosts, external_hosts, firewall)
    
    # Configurar servidor web para testes
    net.get('h6').cmd('python3 -m http.server 80 > /tmp/webserver_h6.log 2>&1 &')
    
    # Configurar regras do firewall
    setup_firewall_rules(firewall)
    
    # Aguardar estabilização
    time.sleep(2)
    
    # Iniciar captura de pacotes
    start_tcpdump(firewall)
    
    # Executar testes
    run_tests(net)
    
    info('*** Topologia configurada com sucesso!\n')
    info('*** Use a CLI para testes manuais\n')
    
    # CLI interativa
    CLI(net)
    
    # Limpeza SEGURA
    cleanup(net)
    net.stop()

def connect_to_internet(net, external_switch):
    """Conecta a rede externa à internet real SEM afetar configurações do host"""
    info('*** Conectando à internet (modo seguro)\n')

    # Limpar interfaces antigas
    os.system(f'sudo ip link delete {VETH_MININET_NAME} 2>/dev/null || true')
    os.system(f'sudo ip link delete {VETH_HOST_NAME} 2>/dev/null || true')

    # Criar par veth
    os.system(f'sudo ip link add {VETH_MININET_NAME} type veth peer name {VETH_HOST_NAME}')
    os.system(f'sudo ip link set {VETH_MININET_NAME} up')
    os.system(f'sudo ip link set {VETH_HOST_NAME} up')

    # Conectar ao switch externo
    external_switch.attach(VETH_MININET_NAME)

    # Configurar IP no host físico na interface virtual
    os.system(f'sudo ip addr flush dev {VETH_HOST_NAME} 2>/dev/null || true')
    os.system(f'sudo ip addr add {VETH_HOST_IP} dev {VETH_HOST_NAME}')

    # SALVAR estado original do sistema
    global ORIGINAL_FORWARDING
    ORIGINAL_FORWARDING = os.popen('sysctl -n net.ipv4.ip_forward').read().strip()
    
    # Ativar roteamento apenas para a simulação
    os.system('sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null')

    # Configurar NAT do host físico
    # Chain específica para fácil remoção
    os.system('sudo iptables -t nat -N MININET_NAT 2>/dev/null || true')
    os.system('sudo iptables -t nat -F MININET_NAT')
    os.system(f'sudo iptables -t nat -I POSTROUTING 1 -s {MININET_EXTERNAL_NET} -o {PHYSICAL_IF} -j MININET_NAT')
    os.system('sudo iptables -t nat -A MININET_NAT -j MASQUERADE')

    # Chain específica para FORWARD rules - para rede 192.168.5.0/24
    os.system('sudo iptables -N MININET_FORWARD 2>/dev/null || true')
    os.system('sudo iptables -F MININET_FORWARD')
    os.system('sudo iptables -I FORWARD 1 -j MININET_FORWARD')
    os.system(f'sudo iptables -A MININET_FORWARD -i {VETH_HOST_NAME} -o {PHYSICAL_IF} -s {MININET_EXTERNAL_NET} -j ACCEPT')
    os.system(f'sudo iptables -A MININET_FORWARD -i {PHYSICAL_IF} -o {VETH_HOST_NAME} -d {MININET_EXTERNAL_NET} -m state --state RELATED,ESTABLISHED -j ACCEPT')

    # Configurar firewall do Mininet
    firewall = net.get('fw')
    firewall.cmd('ip route del default 2>/dev/null || true')
    firewall.cmd(f'ip route add default via {VETH_HOST_ADDR}')

    # Adicionar rota de retorno para rede interna
    os.system(f'sudo ip route replace 10.0.0.0/28 via 192.168.5.1 dev {VETH_HOST_NAME}')
    

def setup_dns(internal_hosts, external_hosts, firewall):
    """Configura servidor DNS usando apenas arquivos temporários"""
    info('*** Configurando DNS (arquivos temporários)\n')
    
    # Hosts externos usam DNS público 
    for host in external_hosts:
        host.cmd('echo "nameserver 8.8.8.8" > /tmp/resolv.conf')
        host.cmd('cat /tmp/resolv.conf > /etc/resolv.conf')  # Apenas dentro do namespace
    
    # Configurar DNS local no firewall usando arquivo temporário
    dns_config = '''# dnsmasq config for Mininet fw (temporary)
interface=fw-eth0
bind-interfaces
listen-address=10.0.0.1
no-resolv
server=8.8.8.8
server=1.1.1.1

# BLOQUEIO: YouTube e Instagram
address=/youtube.com/127.0.0.1
address=/www.youtube.com/127.0.0.1

address=/instagram.com/127.0.0.1
address=/www.instagram.com/127.0.0.1

log-queries
log-facility=/tmp/dnsmasq-fw.log
'''
    
    # Criar arquivo de configuração temporário
    fw_conf_path = '/tmp/dnsmasq-fw.conf'
    with open(fw_conf_path, 'w') as f:
        f.write(dns_config)
    
    # Iniciar dnsmasq com arquivo temporário e PID file
    firewall.cmd('pkill dnsmasq || true')  # Para processos anteriores
    firewall.cmd(f'dnsmasq --conf-file={fw_conf_path} --pid-file=/tmp/dnsmasq-fw.pid &>/tmp/dnsmasq-fw.stdout &')
    
    # Forçar hosts internos a usar DNS do firewall (apenas dentro do namespace)
    for host in internal_hosts:
        host.cmd('echo "nameserver 10.0.0.1" > /tmp/resolv.conf')
        host.cmd('cat /tmp/resolv.conf > /etc/resolv.conf')
        host.cmd('echo "nameserver 8.8.8.8" >> /etc/resolv.conf')  # Fallback

def setup_firewall_rules(fw):
    """
    Configura regras do firewall
    """
    info('*** Configurando regras do firewall\n')
    
    # Habilitar forwarding
    fw.cmd('sysctl -w net.ipv4.ip_forward=1')
    
    # Limpar regras existentes
    fw.cmd('iptables -F')
    fw.cmd('iptables -t nat -F')
    fw.cmd('iptables -X')
    fw.cmd('iptables -t nat -X')
    
    # Políticas padrão
    fw.cmd('iptables -P INPUT DROP')
    fw.cmd('iptables -P FORWARD DROP')
    fw.cmd('iptables -P OUTPUT ACCEPT')
    
    # ====================
    # CADEIA: INPUT
    # ====================

    fw.cmd('iptables -A INPUT -i lo -j ACCEPT')
    fw.cmd('iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT')
    fw.cmd('iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT')
    fw.cmd('iptables -A INPUT -i fw-eth0 -s 10.0.0.0/28 -p udp --dport 53 -j ACCEPT')  # DNS interno
    fw.cmd('iptables -A INPUT -i fw-eth0 -s 10.0.0.0/28 -p tcp --dport 22 -j ACCEPT')  # SSH interno
    
    # ====================
    # CADEIA: FORWARD  
    # ====================
    
    # REGRA 1: Permitir ICMP interno 
    fw.cmd('iptables -A FORWARD -s 10.0.0.0/28 -d 10.0.0.0/28 -p icmp -j ACCEPT')
    
    # REGRA 2: Bloquear ICMP externo da rede interna
    fw.cmd('iptables -A FORWARD -i fw-eth0 -o fw-eth1 -s 10.0.0.0/28 -p icmp --icmp-type echo-request -j DROP')
    fw.cmd('iptables -A FORWARD -i fw-eth0 -o fw-eth1 -s 10.0.0.0/28 -p icmp --icmp-type 30 -j DROP')
    
    # REGRA 3: Permitir HTTP/HTTPS da rede interna
    fw.cmd('iptables -A FORWARD -i fw-eth0 -o fw-eth1 -s 10.0.0.0/28 -p tcp --dport 80 -j ACCEPT')
    fw.cmd('iptables -A FORWARD -i fw-eth0 -o fw-eth1 -s 10.0.0.0/28 -p tcp --dport 443 -j ACCEPT')
    
    # REGRA 4: Permitir DNS da rede interna
    fw.cmd('iptables -A FORWARD -i fw-eth0 -o fw-eth1 -s 10.0.0.0/28 -p udp --dport 53 -j ACCEPT')
    fw.cmd('iptables -A FORWARD -i fw-eth0 -o fw-eth1 -s 10.0.0.0/28 -p tcp --dport 53 -j ACCEPT')
    
    # REGRA 5: Permitir tráfego estabelecido
    fw.cmd('iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT')
    
    # NAT para rede interna
    fw.cmd('iptables -t nat -A POSTROUTING -o fw-eth1 -s 10.0.0.0/28 -j MASQUERADE')
    
    info('*** Regras do firewall aplicadas:\n')
    print(fw.cmd('iptables -L FORWARD -v -n'))

def start_tcpdump(firewall):
    """Inicia captura tcpdump"""
    info('*** Iniciando captura de pacotes no firewalln')
    
    # Parar capturas anteriores
    firewall.cmd('pkill tcpdump || true')
    
    # Iniciar capturas com PID files
    firewall.cmd('tcpdump -i fw-eth0 -w ./fw-eth0.pcap &')
    firewall.cmd('tcpdump -i fw-eth1 -w ./fw-eth1.pcap &')
    
    info('*** Captura iniciada (arquivos em ./fw-eth*.pcap)\n')

def run_tests(net):
    """Executa testes automatizados sem afetar configurações do host"""
    h1, h6 = net.get('h1', 'h6')
    
    info('\n=== TESTES AUTOMATIZADOS===\n')
    
    # Teste 1: ICMP interno permitido
    info('Teste 1: Ping interno (h1 -> h2) - DEVE FUNCIONAR\n')
    result = h1.cmd('ping -c 2 -W 1 10.0.0.3')
    info('✓ Sucesso\n') if '2 received' in result else info('✗ Falha\n')
    
    # Teste 2: ICMP externo bloqueado
    info('Teste 2: Ping externo (h1 -> h5) - DEVE SER BLOQUEADO\n')
    result = h1.cmd('ping -c 2 -W 1 192.168.5.10')
    info('✓ Sucesso\n') if '0 received' in result else info('✗ Falha\n')
    
    # Teste 3: HTTP local permitido
    info('Teste 3: HTTP local (h1 -> h6:80) - DEVE FUNCIONAR\n')
    result = h1.cmd('curl -s -I --connect-timeout 3 http://192.168.5.20:80')
    info('✓ Sucesso\n') if 'HTTP' in result else info('✗ Falha\n')
    
    # Teste 4: HTTP internet permitido (usando IP para evitar DNS do host)
    info('Teste 4: HTTP internet (h1 -> exemplo.org via IP) - DEVE FUNCIONAR\n')
    result = h1.cmd('curl -s --connect-timeout 5 -I http://80.172.227.9/')
    info('✓ Sucesso\n') if 'HTTP' in result else info('✗ Falha\n')
    
    # Teste 5: DNS YouTube bloqueado
    info('Teste 5: DNS YouTube (h1 -> youtube.com) - DEVE SER BLOQUEADO\n')
    result = h1.cmd('nslookup youtube.com 10.0.0.1')
    info('✓ Sucesso\n') if '127.0.0.1' in result else info('✗ Falha\n')
    
    # Teste 6: DNS Instagram bloqueado
    info('Teste 6: DNS Instagram (h1 -> instagram.com) - DEVE SER BLOQUEADO\n')
    result = h1.cmd('nslookup instagram.com 10.0.0.1')
    info('✓ Sucesso\n') if '127.0.0.1' in result else info('✗ Falha\n')
    
    # Teste 7: DNS sites permitidos funcionando
    info('Teste 7: DNS sites permitidos (h1 -> google.com) - DEVE FUNCIONAR\n')
    result = h1.cmd('nslookup google.com 10.0.0.1')
    info('✓ Sucesso\n') if 'Name:' in result else info('✗ Falha\n')
    
    # Teste 8: h5 pode acessar YouTube
    info('Teste 8: h5 acessando YouTube - DEVE FUNCIONAR\n')
    result = h5.cmd('curl -s --connect-timeout 10 -I http://youtube.com/')
    info('✓ Sucesso\n') if 'HTTP' in result else info('✗ Falha\n')
    
    info('\n=== TESTES CONCLUÍDOS ===\n')

def cleanup(net):
    """Remove as configurações criadas pelo script"""
    info('*** Iniciando limpeza segura\n')
    
    # Parar capturas tcpdump no firewall
    firewall = net.get('fw')
    firewall.cmd('pkill tcpdump || true')
    firewall.cmd('rm -f /tmp/tcpdump-eth0.pid /tmp/tcpdump-eth1.pid 2>/dev/null || true')
    
    # Parar dnsmasq no firewall
    firewall.cmd('pkill dnsmasq || true')
    firewall.cmd('rm -f /tmp/dnsmasq-fw.pid /tmp/dnsmasq-fw.stdout 2>/dev/null || true')
    
    # Remover interfaces virtuais
    os.system(f'sudo ip link delete {VETH_MININET_NAME} 2>/dev/null || true')
    os.system(f'sudo ip link delete {VETH_HOST_NAME} 2>/dev/null || true')
    
    # Remover rota específica da rede interna
    os.system(f'sudo ip route del {MININET_INTERNAL_NET} 2>/dev/null || true')
    
    # Remover chains específicas do Mininet
    os.system(f'sudo iptables -t nat -D POSTROUTING -s {MININET_EXTERNAL_NET} -o {PHYSICAL_IF} -j MININET_NAT 2>/dev/null || true')
    os.system('sudo iptables -t nat -F MININET_NAT 2>/dev/null || true')
    os.system('sudo iptables -t nat -X MININET_NAT 2>/dev/null || true')
    
    os.system('sudo iptables -D FORWARD -j MININET_FORWARD 2>/dev/null || true')
    os.system('sudo iptables -F MININET_FORWARD 2>/dev/null || true')
    os.system('sudo iptables -X MININET_FORWARD 2>/dev/null || true')
    
    # Restaurar forwarding original
    global ORIGINAL_FORWARDING
    if 'ORIGINAL_FORWARDING' in globals() and ORIGINAL_FORWARDING.strip() == '0':
        os.system('sudo sysctl -w net.ipv4.ip_forward=0 > /dev/null')
    else:
        os.system('sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null')
    
    # Remover arquivos temporários
    os.system('sudo rm -f /tmp/dnsmasq-fw.conf /tmp/dnsmasq-fw.log 2>/dev/null || true')
    os.system('sudo rm -f /tmp/fw-eth0.pcap /tmp/fw-eth1.pcap 2>/dev/null || true')
    
    info('*** Sistema restaurado - configurações do host preservadas\n')

# Variável global para armazenar estado original
ORIGINAL_FORWARDING = None

if __name__ == '__main__':
    setLogLevel('info')
    setup_network()
