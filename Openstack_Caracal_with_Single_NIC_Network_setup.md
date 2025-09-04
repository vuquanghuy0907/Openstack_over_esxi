**Networking setup for running OpenStack on top of VMware vCenter/ESXi**
# [Setup Summary]
We got a single NIC on all hosts - ens160 that is in LAN network 192.168.25.0/24
We set the hosts file as following:
```bash
192.168.25.10   aio00
192.168.25.11   aio01
192.168.25.12   aio02
192.168.25.13   aio03
192.168.25.14   aio04
192.168.25.15   aio05
```
Single physical NIC (ens160) → enslaved into br0
Management (192.168.25.0/24) + VM external/floating IP (same subnet!) both traverse br0
Host IP moved OFF ens160 → now bound to br0
The neutron_external_interface planned via veth pair into br0

```bash
   [VM mgmt+ext traffic] ─┐
                          │
 ens160 (no IP) ──> br0 (IP: 192.168.25.x/24, gw 192.168.25.1) ──> upstream LAN
                          │
      [Host mgmt SSH] ────┘
```

This highlights:
- ens160 has no IP anymore (just a bridge member)
- br0 owns the host's management IP
- Same 192.168.25.x subnet is used for both host management and OpenStack external VM traffic, so they share the same wire

# [Detail]
**before vs after** network ASCII diagrams for comparision:

---

### **Before (plain NIC, no bridge)**

```
+---------------- Host aio01 ----------------+
|                                            |
|   ens160 (IP: 192.168.25.11/24)            |
|      |                                     |
|      |  (Mgmt SSH + VM external traffic)   |
|      v                                     |
|   Upstream LAN (192.168.25.0/24)           |
|                                            |
|   [No br0, no veth-ext yet]                |
|                                            |
+--------------------------------------------+
```

* Host has IP directly on `ens160`.
* Both **host management** and **VM external traffic** go through the same NIC → LAN.
* No bridge separation yet.

---

### **After (bridge migration: ens160 → br0, IP offloaded)**

```
+---------------- Host aio01 ----------------+
|                                            |
|   ens160 (no IP)                           |
|      |                                     |
|      v                                     |
|   br0 (IP: 192.168.25.11/24)  <── SSH mgmt |
|      ^                                     |
|      |                                     |
|   +--+--- veth-br <────┐                   |
|   |                    |                   |
|   |   veth-ext (neutron_external_interface)|
|   |                                          to neutron (br-ex)
|   |                                          NAT/FIP, DVR, etc
|                                            |
|   +----------- Guests (VMs) ---------------+
|   |                                        |
|   |   VM vNICs → tap devices → OVS/OVN →   |
|   |        … → veth-ext → br0 → LAN        |
|   |                                        |
|   +----------------------------------------+
|                                            |
|   Upstream LAN (192.168.25.0/24)           |
+--------------------------------------------+
```

---

### Key Points in “After” design:

* **ens160**: enslaved to `br0`, no IP.
* **br0**: owns host mgmt IP (e.g., `192.168.25.11`). Host SSH, keepalived VIP, HAproxy VIP all land here.
* **veth pair (veth-ext ↔ veth-br)**: provides “neutron external interface” for floating IP / provider network. One end given to neutron (via `neutron_external_interface`), the other plugged into `br0`.
* **VMs**: their traffic reaches external LAN through OVS/OVN (or linuxbridge), then through veth-ext → br0 → LAN.
* **Same subnet 192.168.25.0/24** carries both host management traffic *and* VM external/FIP traffic.

---

# 🛰 Technical Analysis: Why I Chose Unified NIC Bridging for OpenStack on vCenter

## 1. Deployment Context

* Normally, OpenStack is deployed on **bare-metal servers** with direct control of physical NICs.
* In my case, I only had access to an **existing VMware vCenter/ESXi environment**, not raw bare metal.
* Each OpenStack node (control, compute, storage) runs as a **VM on top of vSphere**.

---

## 2. Why the Traditional Multi-NIC Approach Failed

In a bare-metal OpenStack cluster:

* I typically configure multiple interfaces (or VLANs):

  * `mgmt0` → Management plane
  * `physnet1` → Tenant/provider networks
  * Optional: storage, external

In vSphere:

* I created **two port groups**, attached to VM NICs (management + provider).
* Deployment appeared fine (ping worked, Ansible post-checks passed), but **Neutron networking consistently failed** (no east-west or north-south VM connectivity).

### Why?

This is a **known limitation** of running OpenStack on top of vSphere:

* ESXi’s **vSwitch networking is “opaque”** to OpenStack.
* It **masks VLANs, spoofed MACs, and ARP behavior**, unless explicitly allowed.
* Neutron expects full control of NICs (promiscuous mode, forged MAC, VLAN trunking).
* Without these, OpenStack’s “provider networks” or “overlay encapsulation” break silently — exactly what I observed.

Reference: [ServerFault – OpenStack instance Neutron issue on ESXi](https://serverfault.com/questions/1150798/openstack-instance-neutron-issue)

---

## 3. My Solution: Unified NIC via Bridge

Instead of separating networks, I collapsed everything into **one NIC → one bridge (`br0`)**:

* `ens160` (VM NIC from ESXi) → `br0` (Linux bridge/OVS).
* IP address moved from `ens160` to `br0`.
* Both **host management traffic** and **VM tenant traffic** flow over the same virtual NIC.

### Why this works (inside vSphere):

* From ESXi’s perspective, there’s only **one port group / one NIC per VM**.
* This avoids all the quirks with VLAN passthrough, forged MAC rejection, and vSwitch security rules.
* OpenStack sees a normal NIC and bridge, and can freely attach VM `tap/veth` interfaces.
* ARP, MAC learning, and routing all behave like they would on bare metal.

---

## 4. Benefits of This Approach in My Context

✅ **Works reliably in VMware ESXi** – avoids the networking quirks that break multi-NIC OpenStack deployments.
✅ **Resource efficient** – no need for multiple port groups or extra NICs.
✅ **Simpler debugging** – single network path, transparent bridging.
✅ **Still flexible** – VLANs, overlays (VXLAN, GRE), and DVR can run on top of this single bridge.

---

## 5. Risks & Mitigations

⚠ **Traffic mixing** – management and tenant traffic share the same NIC.

* Acceptable in my case, as traffic profile is modest.
* Could be improved later with VLAN separation if vSwitch security is relaxed.

⚠ **Not a production best practice on bare metal** – but on vSphere this is the only practical option without full ESXi reconfiguration.

---

## 6. Conclusion

* The **traditional bare-metal model** (multi-NIC/provider networks) failed due to **ESXi’s restrictive vSwitch networking model**.
* After 2 months of troubleshooting, the reliable solution was the **unified NIC + bridge design**.
* This design aligns with my **real constraint** (running on top of VMware instead of bare metal), while still delivering functional OpenStack networking for my environment.
* For production-grade bare-metal deployments, I would still recommend the separated-network approach — but here, the **bridge model is the only viable choice**.

---

###### Targeted Ubuntu 22.04 ######
# Network topology: Openstack over VCenter
```bash
                          +--------------------+
                          |   Upstream Switch  |
                          | (192.168.25.0/24)  |
                          +---------+----------+
                                    |
                     -------------------------------
                     |             |             |
                (vSwitch)     (vSwitch)     (vSwitch)
                 ESXi01        ESXi02        ESXi03
                     |             |             |
(This below list of vcenter guests (VM: aio0X) is just for presentation, actually we will have 6 hosts: aio00 -> aio05, but we will only use aio01 to aio05 for openstack deployment. aio00 will be kolla-ansible server for running deployment)
                     |             |             |
                     |             |             |
              +------+------+ +------+------+ +---------+
              |  VM: aio01 | |  VM: aio02 | |  VM: aio03 | <--- VCenter guests, ubuntu server 24.04
              | Controller | |  Compute   | |  Compute   | 
              +------------+ +------------+ +------------+
                     |             |             |
                 ens160        ens160        ens160
                     |             |             |
                  +--+--+       +--+--+       +--+--+
                  | br0 |       | br0 |       | br0 |
                  +--+--+       +--+--+       +--+--+
                     |             |             |
   ---------------------------------------------------------------
   |                |               |               |             |
Management     API Traffic     Tenant VXLAN     Provider VLAN     Storage
Traffic        (Keystone,      (VM Overlay)     (Flat/Tagged)     Traffic
               Nova, etc.)
```
* **Environment:** OpenStack on top of VMware vCenter/ESXi
* **Network:** Single NIC per host (`ens160`), bridged into `br0`
* **Traffic:** Management + API + Tenant (VM) traffic multiplexed over the same bridge
* **Hosts:** aio01 (controller/network), aio02–aio05 (compute + storage)
* **Connectivity:** All hosts tied into the same physical network (`192.168.25.0/24`) through ESXi vSwitch → upstream physical network.

### 📝 Explanation of Flow

* **Single NIC approach**:

  * `ens160` is enslaved into `br0`.
  * IP (e.g., `192.168.25.11`) lives on `br0`, not `ens160`.
  * All OpenStack services (API, Management, Overlay, Provider) ride on the same physical network.

* **Controller (aio01)**: Runs control-plane + Neutron network services (DVR, L3 agents, etc.).

* **Compute (aio02–aio05)**: Run nova-compute, libvirt, and connect VM tap interfaces to `br0` via OVS.

* **ESXi vSwitch**: Acts only as a pass-through uplink to the physical network, not handling VLANs/complex switching.

## 🔄 Understanding Network Architecture (Generic)

### Bridge Layer 2 vs. virtual NICs Layer 3

A critical concept to understand is that **bridges operate at Layer 2** (Data Link Layer) of the OSI model:

- Bridges forward frames based on MAC addresses, not IP addresses
- They don't inherently perform routing functions (Layer 3)
- When you assign an IP to a bridge, it's primarily for management and gateway purposes
- You cannot directly ping external addresses from a bridge interface (`ping -I br-exnat 8.8.8.8` will fail)
- You can "plugin" virtual NICs to Bridges


### Network Topology

Our setup will use:
- **Internal Network**: Neutron external interface veth end (veth-ext) → br0 → External network or virtual routing between openstack guests
- **External Network**: Linux bridge ('br0' - 192.168.25.0/24 - ens160 port) <--> Wifi Ethernet NIC 'ens160' 
- **Connectivity**: br-ex (openstack created) <--> veth-br -- veth-ext (neutron external interface) <--> br0 (ens160 port) <--> External network
- **External Network NIC for Netron**: [Openstack network via br-ex] <--> br-exnat <--> ens160 <--> External network
- **Check your device names**:
---

## 📋 Prerequisites

- Ubuntu/Debian Linux system (22.04, 24.04)
- Administrative (sudo) privileges
- 2 Physical network interfaces (WiFi or Ethernet), we may use  1 Physical network interface + 1 Virtual bridge
- At least 16GB RAM and 4 CPU cores for Kolla
- 100GB+ free disk space
---

---

## 📋 Step-by-Step Guide

### 0️⃣ Pre-Setup: Hostname & User

#### Set hostname on each node:

```bash
sudo hostnamectl set-hostname aio0X # For each hosts specified as above
```

# Host file `/etc/hosts` add
```bash
192.168.25.10   aio00
192.168.25.11   aio01
192.168.25.12   aio02
192.168.25.13   aio03
192.168.25.14   aio04
192.168.25.15   aio05
```

#### Create deployer user and assign groups (run on all nodes):

```bash
sudo useradd -m -s /bin/bash deployer
sudo passwd deployer # Set your own password for this user. Keep it secure guys
sudo usermod -aG sudo,docker deployer
echo "deployer ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/deployer
sudo chmod 0440 /etc/sudoers.d/deployer
```
########### FROM NOW ON, WE WILL ASSUME THAT WE ARE RUNNING AS `deployer` USER ###########

### 🔐 Passwordless SSH Setup for all 5 hosts (required for Kolla-Ansible)

# 1️⃣ Generate SSH key pair (on aio00 node)
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
```

# 2️⃣ Copy public key to all nodes. On aio00
```bash
for host in 192.168.25.10 192.168.25.11 192.168.25.12 192.168.25.13 192.168.25.14 192.168.25.15; do
    ssh-copy-id -i ~/.ssh/id_ed25519.pub deployer@$host
done
```

# 3️⃣ Verify SSH access. On aio00
```bash
for host in 192.168.25.10 192.168.25.11 192.168.25.12 192.168.25.13 192.168.25.14 192.168.25.15; do
    ssh deployer@$host 'hostname'
done
```
# ✅ No password prompts.
### 1️⃣ Network Configuration (on all nodes)

# VSphere-specific note: Config to enable these settings:
[*] Policies
  [!] Security
    - Promiscuous mode	Accept
    - MAC address changes	Accept
    - Forged transmits	Accept

# Next, on each host, we got a single ens160 NIC that plugged into 192.168.25.0/24 LAN. Now, we will connect it to bridge and offload ip to it
# We config the netplan file `/etc/netplan/01-br0.yaml` as following on each hosts:
```bash
network:
  version: 2
  renderer: networkd
  ethernets:
    ens160:
      dhcp4: false
      dhcp6: false
  bridges:
    br0:
      interfaces: [ens160]
      addresses: [192.168.25.1X/24]
      routes:
        - to: default
          via: 192.168.25.1
      nameservers:
        addresses: [8.8.8.8,8.8.4.4]
```
# Note to change the IP (192.168.25.1X) properly to each hosts
# Then run netplan apply
```bash
sudo netplan try
sudo netplan apply
```
# If you assign temporary ips on all hosts already via ens160, you can populate the netplan config file with. On aio00
```bash
for i in {1..5}; do
  ip="192.168.25.$((10 + i))"   # aio01=192.168.25.11 ... aio05=192.168.25.15
  ssh aio0$i "echo 'network: {config: disabled}' | sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg >/dev/null && \
    sudo tee /etc/netplan/01-br0.yaml >/dev/null <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ens160:
      dhcp4: false
      dhcp6: false
  bridges:
    br0:
      interfaces: [ens160]
      addresses: [$ip/24]
      routes:
        - to: default
          via: 192.168.25.1
      nameservers:
        addresses: [8.8.8.8,8.8.4.4]
EOF
    sudo chmod 0600 /etc/netplan/01-br0.yaml
    # sudo netplan apply"
done
```
# Then on the console of each host, run netplan apply. I said on console (like physical access), not via ssh because in the process of changing network setting from interface ens160 to bridge br0, the connection will be terminated, and thus ssh session will be gone. Disconnect in the progress might result in undesired state.

# Check from aio00
```bash
for host in aio01 aio02 aio03 aio04 aio05; do ssh $host "hostname"; done
```

# [Enable kernel modules] Next, we enable required kernel modules for Openstack networking (I'm not sure we need this, but doesn't hurt to run)
# On aio00, create this file in `~/enable_kernel_modules.sh` as deployer user
```bash
#!/bin/bash

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/tmp/network-test-$(date +%Y%m%d-%H%M%S).log"
# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

print_header() {
    log ""
    log "${BLUE}================================================${NC}"
    log "${BLUE}$1${NC}"
    log "${BLUE}================================================${NC}"
}

print_section() {
    log ""
    log "${YELLOW}--- $1 ---${NC}"
}

print_success() {
    log "${GREEN}â $1${NC}"
}

print_error() {
    log "${RED}â $1${NC}"
}

print_warning() {
    log "${YELLOW}â  $1${NC}"
}

print_info() {
    log "${CYAN}â¹ $1${NC}"
}

print_test() {
    log "${PURPLE}ð§ª $1${NC}"
}

check_kernel_modules() {
    print_section "Checking Required Kernel Modules"

    local modules=("bridge" "br_netfilter" "iptable_nat" "ip_tables")
    local missing_modules=()

    for module in "${modules[@]}"; do
        if lsmod | grep -q "^$module"; then
            print_success "Module $module is loaded"
        else
            print_warning "Module $module not loaded, attempting to load..."
            if modprobe "$module" 2>/dev/null; then
                print_success "Successfully loaded module $module"
            else
                print_warning "Could not load module $module (may not be available)"
                missing_modules+=("$module")
            fi
        fi
    done

    if [ ${#missing_modules[@]} -gt 0 ]; then
        print_warning "Missing modules: ${missing_modules[*]} - some tests may be limited"
    fi
}

check_kernel_modules

```

# Then run this to enable the kernel module on all hosts. On aio00
```bash
for node in aio01 aio02 aio03 aio04 aio05; do echo "=== Enable kernel modules on $node ==="; scp ~/enable_kernel_modules.sh $node:/tmp/; ssh $node "sudo chmod +x /tmp/enable_kernel_modules.sh; sudo bash  /tmp/enable_kernel_modules.sh"; done;
```

# [Enable require flag] Next, we enable all of the required flag on the host (ip forwarding, etc). On aio00
```bash
for h in aio01 aio02 aio03 aio04 aio05; do \
  ssh $h "sudo sysctl -w net.ipv4.ip_forward=1 \
                net.ipv4.conf.all.rp_filter=0 \
                net.ipv4.conf.default.rp_filter=0 \
                net.ipv4.conf.all.arp_ignore=1 \
                net.ipv4.conf.all.arp_announce=2 \
                net.bridge.bridge-nf-call-iptables=0 \
                net.bridge.bridge-nf-call-ip6tables=0 \
                net.ipv4.ip_nonlocal_bind=1"; \
done
```

# Enable IP forwarding for all hosts, no persistent
```bash
for host in aio01 aio02 aio03 aio04 aio05; do
    ssh $host "sudo sysctl -w net.ipv4.ip_forward=1"
    echo "=== $host ip forwarding enabled ==="
done
```

# [Creating veth pair] And we also bring on the veth pair for later use as neutron external interface. On aio00
```bash
for i in {1..5}; do
  ip="192.168.25.$((10 + i))"   # aio01=192.168.25.11 ... aio05=192.168.25.15
  ssh aio0$i "sudo ip link add veth-br type veth peer name veth-ext
  sudo ip link set veth-br master br0
  sudo ip link set veth-br up
  sudo ip link set veth-ext up"
done
```
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------

# OpenStack Deployment utilizing Kolla-Ansible on Ubuntu 24.04.2
# Ref: Openstack 2024.1 installation guide
  # - https://docs.openstack.org/kolla-ansible/2024.1/user/quickstart.html
  # Multinode installation guide
  # - https://docs.openstack.org/kolla-ansible/2024.1/user/quickstart-development.html
  # - https://docs.openstack.org/kolla-ansible/2024.1/user/virtual-environments.html
  # - https://docs.openstack.org/kolla-ansible/2024.1/user/multinode.html

### Our networking model will be as following
```
[ VM (Floating IP) ]
         │
     (Neutron)
         │
   ┌───────────────┐
   │     br-ex     │    ← created by Neutron L3/OVS agent
   └───────────────┘
          │
          │   ← veth pair connects br-ex <--> br0
          │
      [   br0   ]    ← main bridge (ens160 enslaved here)
    (mgmt + tenant + external)
          │
      [ ens160 ]      ← real external NIC (ESXi vSwitch uplink)
          │
   ┌─────────────────┐
   │ Upstream Network│   ← 192.168.25.0/24 (mgmt + public net)
   └─────────────────┘

```
## We will config this later

# Next, we will install kolla-ansible from aio00 to all hosts. 
# I heavily recommend to keep the multinode file and globals.yml config as-is to this guidance, and the installation process should be done according to the referenced links above instead of the following section, unless you got error along the way and need to go slowly for troubleshooting, because the below step-by-step guidance is written for openstack yoga version and not yet be modified for caracal or newer version
# As newer openstack version may require newer python, kolla, etc (Although the below note, I still note some specific version for caracel - 2024.1)

##  Setup Kolla-Ansible [aio00 only unless specifically stated otherwise]

```bash
# 1. Update system packages
sudo apt update && sudo apt upgrade -y

# 2. Install essential development and Python dependencies
sudo apt install -y \
  python3-pip python3-dev \
  libssl-dev libffi-dev \
  gcc build-essential \
  libxml2-dev libxslt1-dev \
  zlib1g-dev libdbus-1-dev libglib2.0-dev \
  python3-venv git

# 3. Check or install Python 3.10 for  Kolla (not python 3.12)
- Check python version
python3 --version
#--> The return should be Python 3.10.*. If not you have to install Python 3.10
- Install Python 3.10 
# a. Install Python 3.10 and create a virtual environment for Kolla
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt install -y python3.10 python3.10-venv python3.10-dev
# b. Verify
which python3.10
#--> `/usr/bin/python3.10`

# 4. Create and activate the virtual environment
sudo rm -rf ~/kolla-venv
python3.10 -m venv ~/kolla-venv
source ~/kolla-venv/bin/activate

# 5. Setup setuptools which compatibility with pbr and Python 3.10+
# pip install "setuptools<69"
sudo pip install -U pip setuptools

# 6. Upgrade pip inside the venv
pip install --upgrade pip

```
### ✅ Step 2. Cleanup Old Deployment (Inventories, Containers, and Dependencies) [Do on all 5 machine, as we need python3.10 and virt-env on all hosts]

> If you're working on a reused or older PC that may have prior Kolla or Docker deployments, it's important to fully clean up before starting fresh.

---

####1. Clean Docker Containers, Volumes, and Images

```bash
# Stop all containers
sudo docker ps -aq | xargs -r sudo docker stop

# Remove all containers
sudo docker ps -aq | xargs -r sudo docker rm -f

# Remove all images
sudo docker images -aq | xargs -r sudo docker rmi -f

# Remove all volumes
sudo docker volume ls -q | xargs -r sudo docker volume rm

# Clean dangling networks
sudo docker network prune -f
```
---

####2. Remove Kolla Configuration Directories

```bash
sudo rm -rf /etc/kolla
sudo rm -rf /opt/kolla

# Delete Only Kolla-related Docker Images
sudo docker images | grep quay.io | awk '{print $3}' | xargs -r sudo docker rmi -f
sudo docker container prune -f
sudo docker image prune -f
sudo docker volume prune -f
```
---

####3. Destroy Existing Kolla Deployments- **Identify Existing Inventory Files**

> Kolla-Ansible uses inventory files (`multinode`, `all-in-one`) to manage deployments.

```bash
find ~ -type f -name "multinode" -o -name "all-in-one"
```

Example output:
```ini
/home/deployer/kolla-ansible/ansible/inventory/all-in-one
/home/deployer/kolla-ansible/ansible/inventory/multinode
/home/deployer/kolla-venv/share/kolla-ansible/ansible/inventory/all-in-one
/home/deployer/kolla-venv/share/kolla-ansible/ansible/inventory/multinode
Notes: Donot delete the new install and delete all other
/home/deployer/kolla-ansible/ansible/inventory/all-in-one
/home/deployer/kolla-ansible/ansible/inventory/multinode

- **(Optional) Destroy all old deployment**

```bash
sudo kolla-ansible destroy -i /home/deployer/kolla-ansible/ansible/inventory/all-in-one --yes-i-really-really-mean-it

kolla-ansible destroy -i /home/deployer/kolla-ansible/ansible/inventory/all-in-one --yes-i-really-really-mean-it

# Destroy multinode deployment
sudo kolla-ansible destroy -i /home/deployer/kolla-ansible/ansible/inventory/multinode --yes-i-really-really-mean-it
kolla-ansible destroy -i /home/deployer/kolla-ansible/ansible/inventory/multinode --yes-i-really-really-mean-it
```

Replace `/path/to/` with your actual inventory file path.

####4. Optional: Clear Residual Package Cache

```bash
sudo apt autoremove --purge -y
sudo apt clean
```

### ✅ Step 3. Setup Kolla-Ansible, Docker CE, and Ansible (caracal) [Do on all 5 machine, as we need python3.10, kolla-ansible, openstack installer (I guess) and virt-env on all hosts]

#### 1. Install kolla-ansible

```bash
source ~/kolla-venv/bin/activate
sudo rm -rf kolla-ansible

git clone -b stable/2024.1 https://opendev.org/openstack/kolla-ansible.git

cd kolla-ansible

pip install -r requirements.txt

pip install .

#Verify
which kolla-ansible
#--> `/home/deployer/kolla-venv/bin/kolla-ansible`
```
#### 2. Install Docker CE (clean and compatible) [Do this on all 5 hosts]
# This step is Optional to download images from `download.docker.com`

```bash
#a. Core Dependencies
sudo apt update
sudo apt install -y ca-certificates curl gnupg lsb-release

## [Keyring action that worth noting]
#b. Add Docker’s GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

#c. Add Docker's GPG key & repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
| sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update -y && sudo apt upgrade -y

    ## [One fix] If the [Keyring action that worth noting] section failed, fix it as following: [I took this fix]
    # 1️⃣ Search for Any Leftover Sources
    grep -R "docker.asc" /etc/apt/sources.list.d /etc/apt/sources.list || true
    # I got the output: /etc/apt/sources.list.d/docker.sources:Signed-by: /etc/apt/keyrings/docker.asc
    # You can see that the problem is that apt is trying to verify against "asc" key instead of "gpg" key. So we're gonna fix it. In case the grep return multiple files referencing, we fix them all
    # 📌 2️⃣ Edit or Remove Old Entries
    sudo vi /etc/apt/sources.list.d/docker.list
    # change from "/etc/apt/keyrings/docker.asc" to "/etc/apt/keyrings/docker.gpg"
    # Or remove duplication if any
    sudo rm /etc/apt/sources.list.d/docker.list
    # and recreate it with your docker.gpg version

    ## [Another fix] If those above keyring-things does not work, try this [I skipped this]
    # Clean up keyring
    sudo rm -f /etc/apt/keyrings/docker.asc
    sudo rm -f /etc/apt/keyrings/docker.gpg
    # Redownload key
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg

#d. Install Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin

#e. Enable Docker
sudo systemctl enable --now docker

#f. (Optional) If you plan to not download from download.docker.com again
sudo sed -i 's/^deb/#deb/' /etc/apt/sources.list.d/docker.list

#g.  Verify
sudo cat /etc/apt/sources.list.d/docker.list
# --> Result should show: #deb ...

#h. Add your user to the docker group
sudo usermod -aG docker $USER
newgrp docker
source ~/kolla-venv/bin/activate

#h. Checking
groups

# --> Should include: docker sudo deployer kolla

docker --version
# --> Should print: Docker version ...
```
---

## Setup Ansible and Verify Default Paths 

### ✅ Step 1. Install Ansible compatible with Caracal (5 hosts, as we need ansible and its dependancies on all 5 host too)

```bash
# ansible-core 2.12.10 = matches Yoga's tested version
# ansible>=5,<6      = provides the meta-package with community collections

(sudo) pip install -U pip setuptools
pip install -U 'ansible>=6,<9'

# Optional: Check versions
ansible --version
docker --version
# Notes:
# - Up to now, we do NOT have ~/.ansible/collections/ installed.
# - Kolla-Ansible will expect required collections there.
# - We will manually install the necessary collections later
```

### ✅ Step 2: Set Owner and Verify Default Paths for Ansible, Kolla-Ansible, and OpenStack [aio0 only, unless state otherwise]

This step ensures you understand where Kolla-Ansible roles expect files to be written and verifies **both path references and ownership**, especially on reused or restricted systems.

####  1. Verify Python Virtual Environment and Kolla-Ansible Role Paths (5 hosts???)

```bash
# Activate your virtual environment
source ~/kolla-venv/bin/activate

#1. Get the virtual environment path
echo "$VIRTUAL_ENV"
# ➤ Output should be something like: /home/deployer/kolla-venv

#2. Locate the Kolla-Ansible role defaults directory
ROLE_DIR=$(find "$VIRTUAL_ENV" -type d -path "*/share/kolla-ansible/ansible/roles" 2>/dev/null)

#3. Confirm the roles directory
echo "Roles dir: $ROLE_DIR"

# ➤ Output should look like: /home/deployer/kolla-venv/share/kolla-ansible/ansible/roles
# ➤  If the return = "", you forgot install ` kolla-ansible": 'pip install .
#4. Verify
ls /home/deployer/kolla-venv/share/kolla-ansible/ansible/roles
# ➤ Output should show roles for kolla-ansible

#5. Extract default path-related variables from role defaults
grep -RHE 'dest:|path:|config_dir:' \
  "$ROLE_DIR"/*/defaults/main.yml \
  | sed -E 's/^[^:]+:[[:space:]]*//' \
  | sort -u
```
- **What These Paths Tell You**?

Kolla-Ansible role defaults often reference:

- Temporary files (e.g., `/tmp/kolla_*`)
- Relative configuration paths (e.g., `openssl.cnf`)
- Optional external service endpoints
- Templated values (e.g., using `{{ }}` syntax for host/project-specific output)

#### 2. Generate and check Runtime-Critical Directories (Used During Actual Deployment) (5 hosts???)

-  **Generate and  check common Kolla/OpenStack runtime directories and ensure your user can write to them**
```bash
sudo rm -rf etc/kolla /opt/kolla  /var/lib/docker
```
```bash
for path in /etc/kolla /opt/kolla /var/lib/docker; do
  echo "Checking permissions on $path"
  sudo mkdir -p "$path"
  sudo chown -R $USER:$USER "$path"
  ls -ld "$path"
done
```
-  **These are  not defined in Ansible role defaults  but are used by**:
- Kolla configuration management
- Docker volume mounts
- Persistent service state (e.g., MariaDB data, RabbitMQ queues)


### ✅ Step 3: Copy and Configure Inventory and Defaults for Kolla-Ansible (5 hosts???)

Kolla-Ansible expects its main configuration and inventory files under `/etc/kolla`. This step prepares that directory and populates it with example files.

#### 1️⃣ Create and Take Ownership of `/etc/kolla`

```bash
source ~/kolla-venv/bin/activate

# Create required directories
sudo mkdir -p /etc/kolla
sudo mkdir -p /etc/kolla/ansible/inventory

# Give current user ownership (for editing)
sudo chown -R "$USER":"$USER" /etc/kolla
```
#### 2️⃣ Locate Example Files in Your Environment

- Find where the example configs are installed inside your venv

```bash
find ~/kolla-venv -type d -name "etc_examples"

# Example output:
# ➤ `/home/deployer/kolla-venv/share/kolla-ansible/etc_examples`
```
#### 3️⃣ Copy Example Configs and Inventories

- Copy default globals and passwords config files

```bash
cp -r ~/kolla-venv/share/kolla-ansible/etc_examples/kolla/* /etc/kolla/
```

- Copy sample inventory files (all-in-one, multinode)

```bash
cp -r ~/kolla-venv/share/kolla-ansible/ansible/inventory/* /etc/kolla/ansible/inventory/
```
#### 4️⃣ Verify Copy Success

- Verify base configuration files

```bash
ls /etc/kolla/
# → globals.yml  passwords.yml  ansible/

# Verify inventories
ls /etc/kolla/ansible/inventory/
# → all-in-one  multinode  registry_credentials.yml
```
### ✅ Step 4: Configure Ansible Inventory and ansible.cfg (Scoped for Kolla-Ansible)

To ensure a consistent environment for deploying Kolla-Ansible, it's best practice to define an Ansible configuration file **local to the inventory**. This avoids system-wide conflicts and ensures Ansible uses the correct Python interpreter and role paths.

#### 1️⃣ Create Inventory-Scoped Ansible Config Directory

```bash
# Activate your virtualenv (if not already)
source ~/kolla-venv/bin/activate

# Ensure the inventory directory exists
mkdir -p /etc/kolla/ansible/inventory
```
#### 2️⃣ Determine Python Interpreter Path

```bash
which python
# ➤ Output: /home/deployer/kolla-venv/bin/python
```

### ✅ Step 5: Prepare Container Volumes for Logs and Config Injection (Kolla-Ansible Safe Setup)

This step ensures necessary directories exist and are safely owned before Kolla-Ansible deployment begins. These folders are used by Kolla for **logs**, **custom configs**, and **container runtime state**.

### 1️⃣ Create Host Directories for Logs and Custom Config Overrides

```bash
source ~/kolla-venv/bin/activate

# These are safe to pre-create
sudo rm -rf  /etc/kolla/config
sudo mkdir -p /etc/kolla/config

# Optional: only if you plan to inject config templates (e.g., config.json)
sudo mkdir -p /etc/kolla/config_files

# Set ownership for deployer
sudo chown -R "$USER":"$USER" /etc/kolla
sudo chown -R "$USER":"$USER" /etc/kolla/config /etc/kolla/config_files

# Verify permissions
ls -ld  /etc/kolla /etc/kolla/config /etc/kolla/config_files
```

### ✅ Summary
| `/etc/kolla/config` | Your override configs (e.g., nova.conf) | ✅ Yes |
| `/etc/kolla/config_files` | For injecting `config.json` templates | ✅ Optional |
⚠️ **Avoid conflicts** with other OpenStack tools by keeping these paths scoped to Kolla.


## Setup and download openstack container images

#### Edit `globals.yml` for pull container images
```bash
sudo vi /etc/kolla/globals.yml
```
# Add/modify these settings (for ubuntu 22.04 or 24.04)
```yml
kolla_base_distro: "ubuntu"
# kolla_install_type: "source"
kolla_install_type: "binary"
openstack_release: "2024.1"
# Network configuration
kolla_internal_vip_address: "192.168.25.254"

# Host side (single NIC)
network_interface: "br0"
api_interface: "br0"
storage_interface: "br0"
tunnel_interface: "br0"

neutron_external_interface: "veth-ext"

enable_haproxy: "yes"
enable_neutron_provider_networks: "yes"
enable_neutron: "yes"
enable_neutron_metadata_agent: "yes"
enable_nova_serialconsole_proxy: "yes"
nova_compute_virt_type: "kvm"

neutron_plugin_agent: "openvswitch"

# Healthcheck options
enable_container_healthchecks: "yes"

# Firewall options
disable_firewall: "true"
```

### ✅ Step 2: Kolla Prepare for Deployment

#### 🔹 1. Bootstrap the Servers

This step prepares your target host (in this case, the same machine) for Kolla deployment. It configures necessary users, Docker, Python interpreter, and other base components.

- **Download colections**

```bash
# Navigate to your inventory directory
cd /etc/kolla/ansible/inventory/

# Activate Python virtual environment
source ~/kolla-venv/bin/activate

# Optional but recommended: disable AppArmor for container compatibility
sudo systemctl stop apparmor
sudo systemctl disable apparmor
sudo ln -vsf /etc/apparmor.d/usr.sbin.libvirtd /etc/apparmor.d/disable

# Disable AppArmor for all hosts. on aio00
for host in aio01 aio02 aio03 aio04 aio05; do
    ssh $host "sudo systemctl stop apparmor; sudo systemctl disable apparmor; sudo ln -vsf /etc/apparmor.d/usr.sbin.libvirtd /etc/apparmor.d/disable"
    echo "=== $host AppArmor disabled ==="
done

# Ensure firewall utility is available ( do this for all hosts)
sudo apt install ufw -y
pip install docker
# Clean up potential environment variable conflicts
unset ANSIBLE_GATHER_SUBSET ANSIBLE_PYTHON_INTERPRETER ANSIBLE_COLLECTIONS_PATH

# Point to the local ansible.cfg for Kolla
export ANSIBLE_CONFIG="$PWD/ansible.cfg"

# Verify interpreter and other settings
ansible-config dump | grep -E 'GATHER_SUBSET|INTERPRETER|ROLES_PATH|COLLECTIONS_PATH'
# → INTERPRETER_PYTHON should point to: /home/deployer/kolla-venv/bin/python

# Dowload Ansible Galaxy collection (yoga?) 
sudo rm -rf  ~/.ansible/collections/ansible_collections/openstack
mkdir -p ~/.ansible/collections/ansible_collections/openstack
cd ~/.ansible/collections/ansible_collections/openstack
sudo rm -rf kolla

# git clone https://opendev.org/openstack/ansible-collection-kolla.git kolla
git clone -b stable/2024.1 https://opendev.org/openstack/ansible-collection-kolla.git kolla
cd kolla
# git checkout tags/yoga-eol -b yoga-eol-local
#ansible-galaxy collection install openstack.kolla

##verify
ansible-galaxy collection list | grep openstack.kolla
# --> results should show: `openstack.kolla 1.0.0` 

ansible-config dump | grep -E 'GATHER_SUBSET|INTERPRETER|ROLES_PATH|COLLECTIONS_PATH'

# ---> COLLECTIONS_PATH must have /home/deployer/.ansible/collections/ansible_collections'
```
# Add/modify these settings for multinode file `/etc/kolla/ansible/inventory/multinode` (for ubuntu 22.04 or 24.04)
```yaml
[control]
aio01 ansible_host=192.168.25.11 ansible_hostname=aio01 ansible_ssh_user=deployer ansible_become=True ansible_private_key_file=/home/deployer/.ssh/id_ed25519

# Add all node as network nodes, just in case. I had bad experience with networking problem and troubleshoot for month which led to nowhere. We also enable dvr in the globals file
# We can specified specific intepreter with aio01 ansible_python_interpreter=/usr/bin/python3.10. But in this case we dont need it
# Network node should be control node
[network]
aio01 ansible_host=192.168.25.11 ansible_hostname=aio01 ansible_ssh_user=deployer ansible_become=True ansible_private_key_file=/home/deployer/.ssh/id_ed25519

[compute]
aio02 ansible_host=192.168.25.12 ansible_hostname=aio02 ansible_ssh_user=deployer ansible_become=True ansible_private_key_file=/home/deployer/.ssh/id_ed25519
aio03 ansible_host=192.168.25.13 ansible_hostname=aio03 ansible_ssh_user=deployer ansible_become=True ansible_private_key_file=/home/deployer/.ssh/id_ed25519
aio04 ansible_host=192.168.25.14 ansible_hostname=aio04 ansible_ssh_user=deployer ansible_become=True ansible_private_key_file=/home/deployer/.ssh/id_ed25519
aio05 ansible_host=192.168.25.15 ansible_hostname=aio05 ansible_ssh_user=deployer ansible_become=True ansible_private_key_file=/home/deployer/.ssh/id_ed25519

[monitoring]
aio01 ansible_host=192.168.25.11 ansible_hostname=aio01 ansible_ssh_user=deployer ansible_become=True ansible_private_key_file=/home/deployer/.ssh/id_ed25519

[storage]
aio02 ansible_host=192.168.25.12 ansible_hostname=aio02 ansible_ssh_user=deployer ansible_become=True ansible_private_key_file=/home/deployer/.ssh/id_ed25519
aio03 ansible_host=192.168.25.13 ansible_hostname=aio03 ansible_ssh_user=deployer ansible_become=True ansible_private_key_file=/home/deployer/.ssh/id_ed25519
aio04 ansible_host=192.168.25.14 ansible_hostname=aio04 ansible_ssh_user=deployer ansible_become=True ansible_private_key_file=/home/deployer/.ssh/id_ed25519
aio05 ansible_host=192.168.25.15 ansible_hostname=aio05 ansible_ssh_user=deployer ansible_become=True ansible_private_key_file=/home/deployer/.ssh/id_ed25519

[deployment]
localhost ansible_connection=local  ansible_ssh_user=deployer ansible_become=True ansible_private_key_file=/home/deployer/.ssh/id_ed25519

# The rest left untouched

```

- **Bootstrap the server(s)**

- **Run bootstrap**
```bash
cd /etc/kolla/ansible/inventory
source ~/kolla-venv/bin/activate
kolla-genpwd
# If the kolla-genpwd requires default file, you can grab it at https://opendev.org/openstack/kolla-ansible/src/branch/master/etc/kolla/passwords.yml
kolla-ansible bootstrap-servers -i /etc/kolla/ansible/inventory/multinode # might also need --extra "gather_facts=true" --skip-tags baremetal

```Note:
The error message "the role 'openstack.kolla.baremetal' was not found" indicates that Ansible, when attempting to execute a Kolla-Ansible playbook, could not locate the specified Ansible role. This typically occurs in the context of deploying or managing an OpenStack environment using Kolla-Ansible on bare metal.
Common Causes and Solutions:
Missing or Incorrectly Installed Kolla-Ansible Dependencies:
Cause: The necessary Ansible Galaxy roles, including openstack.kolla.baremetal, might not have been installed or are not accessible in the expected locations.
Solution: Ensure Kolla-Ansible and its dependencies are properly installed. This often involves running ansible-galaxy install -r requirements.yml within the Kolla-Ansible directory, or as part of the Kolla-Ansible installation process, to fetch the required roles.
```

- **Debugs: You may need revise docker_sdk tasks if bootstrap-servers False in Ubuntu 24.04**
```bash
### Revise docker_sdk/tasks/main.yml
nano ~/.ansible/collections/ansible_collections/openstack/kolla/roles/docker_sdk/tasks/main.yml

#revise the 'pip3' line and save
- name: Install docker SDK for python
....
executable: "{{ virtualenv is none | ternary('pip3', omit) }}"
## -->
- name: Install docker SDK for python
---
executable: "{{ virtualenv is none | ternary('/home/deployer/kolla-venv/bin/pip3', omit) }}

# Re  bootstrap-servers
kolla-ansible bootstrap-servers -i /etc/kolla/ansible/inventory/multinode

```

## ✅ Expected Results

- The `kolla` user will be created on the local machine.
- Docker and Python dependencies will be installed.
- SSH key exchange and Ansible setup will be validated.

- **Clean all old docker images (do this on 5 hosts) [Optional. If you have fresh machine, skip this step]** 
```bash
source ~/kolla-venv/bin/activate
## Stop every container that was started by Kolla (they all carry the 'kolla_version' label)
docker ps -q --filter "label=kolla_version" | xargs -r docker stop

## (Options) Delete all old dicker images (if ones need)
sudo docker stop $(sudo docker ps -aq)
sudo docker rm -f $(sudo docker ps -aq)
sudo docker rmi -f $(sudo docker images -aq)
sudo docker volume rm $(sudo docker volume ls -q)
sudo docker system prune -a --volumes -f

## Stop libvirtd if one need
sudo systemctl stop libvirtd
sudo systemctl disable libvirtd
sudo pkill -f libvirtd
sudo rm -f /var/run/libvirt/libvirt-sock

## Check NICs
sudo apt install -y libdbus-1-dev libglib2.0-dev
pip3 install dbus-python
ip a

##--> The resuls should show:
##--> local NIC (10.10.10.*/24) and external NIC (192.168.25.*/24)

## Ping check (use your real IP)
ping -c 3 10.10.10.1
ping -c 3 8.8.8.8

## Detele the .254 ips in ones avalable
# Verify IP for NICs
ip a
# You may need delete some IP
sudo ip addr del 10.10.10.254/32 dev br-exnat
sudo ip addr del 192.168.25.254/32 dev ens160
```
#### Revise checking tasks (only for ubuntu 24.04)
```bash
nano /home/deployer/kolla-venv/share/kolla-ansible/ansible/roles/prechecks/tasks/host_os_checks.yml
add a line below the line: `- ansible_facts.distribution_version != '24.04'
```ini
  when:
    - ansible_facts.distribution_release not in host_os_distributions[ansible_facts.distribution]
    - ansible_facts.distribution_version not in host_os_distributions[ansible_facts.distribution]
    - ansible_facts.distribution_major_version not in host_os_distributions[ansible_facts.distribution]
    - ansible_facts.distribution_version != '24.04'
```

####  Run kolla-ansible precheck
- **Check IP/hotsname for your local host **
```bash
sudo docker ps -q | xargs -r sudo docker stop
sudo ip neigh flush all
ip a show
hostname -f
#---> eg. IP Results show: 192.168.25.100
#--->  hostname show: aio
```
- **Setting IP for your local hosts**
```bash
sudo nano /etc/hosts
# Double check the line to hosts (use your host name)
192.168.25.100 aio
```
- **Run checking**
```bash
cd /etc/kolla/ansible/inventory
source ~/kolla-venv/bin/activate
kolla-ansible prechecks -i /etc/kolla/ansible/inventory/multinode
```
-**Debug**
You may need revise rabbitmq roles if it raise errors. If not let it as original one (This is only for "yoga" version).
-**Revise rabbitmq roles**
```bash
vi /home/deployer/kolla-venv/share/kolla-ansible/ansible/roles/rabbitmq/tasks/precheck.yml

#Revise 1:
- name: Check if all rabbit hostnames are resolvable
....
  command: "getent {{ nss_database }} {{ hostvars[item].ansible_facts.hostname }}"

--->
- name: Check if all rabbit hostnames are resolvable
....
  shell: |
    getent {{ nss_database }} {{ hostvars[item].ansible_facts.hostname }} | grep STREAM | awk '{print $1}' | sort -u
 
#Revise 2:
  when:
     - not item.1 is match('^'+('api' | kolla_address(item.0.item))+'\\b')
     
  --->
    when: item.1 != hostvars[item.0.item]['ansible_' + api_interface]['ipv4']['address']

```

### ✅ Step 4: Generate configs
```bash
cd /etc/kolla/ansible/inventory/

# Activate Python virtual environment
source ~/kolla-venv/bin/activate
sudo docker ps -q | xargs -r sudo docker stop # I don't know why do we need to disable docker 1st. I just skipped this
kolla-ansible genconfig -i /etc/kolla/ansible/inventory/multinode
```
### ✅ Step 5: Pull or Build Docker Images Locally
# ✅ Step 5: Pull or Build Docker Images Locally

## 1. Pull or Build Docker Images Locally

### Option A: Pull from Official Registry

1. **Activate the virtual environment**:

   ```bash
   cd /etc/kolla/ansible/inventory/
   source ~/kolla-venv/bin/activate
   ```

2. **Verify Python interpreter settings**:
   Ensure the Python interpreter is correctly set to use your virtual environment.

   ```bash
   unset ANSIBLE_GATHER_SUBSET ANSIBLE_PYTHON_INTERPRETER ANSIBLE_COLLECTIONS_PATH
   export ANSIBLE_CONFIG="$PWD/ansible.cfg"
   
   ansible-config dump | grep -E 'GATHER_SUBSET|INTERPRETER|ROLES_PATH|COLLECTIONS_PATH'
   ```
   - You should see something like:
     ```bash
     INTERPRETER_PYTHON(/etc/kolla/ansible/inventory/ansible.cfg) = /home/deployer/kolla-venv/bin/python
     ```

3. **Pull the Docker images (I skipped this as my `kolla-ansible deploy` ran well)**:
# [Note]: Must check and take over the ownership of the /var/lib/docker/tmp/ (need to be manually done on 5 machines)
  ```bash
  sudo systemctl restart docker # <-- I skipped this
  sudo rm -rf /var/lib/docker/tmp/ # <-- I skipped this
  sudo mkdir /var/lib/docker/tmp # <-- Maybe, if the dir not exist yet
  # You may need to take ownership of /var/lib/docker/overlay2 also in case the pulling fail with something like (Ex: "Unknown error message: failed to register layer: symlink ../3d11b2a600ddb48c2cbf6ef525f5408e65a89cc6ed0a7be08ac0a1238971dae6/diff /var/lib/docker/overlay2/l/STKL7DUOOZYU23HJKMYRHHX2TH: no such file or directory")
  sudo chown -R "$USER":"$USER"  /var/lib/docker/overlay2
  # Or to be safe, just take over the ownership of /var/lib/docker/ if you want
  sudo chown -R "$USER":"$USER"  /var/lib/docker/
  ```

# If everything's good, execute image pulling from aio0
```bash
kolla-ansible pull -i /etc/kolla/ansible/inventory/multinode
```

4. **Check the pulled images**:

   After pulling the images, verify that they are available:

   ```bash
   sudo docker image ls
   # OR sudo docker image ls | grep -i yoga
   ```

   - You should see containers with the `tag=yoga`.

---

### Option B: Build Locally (e.g., if official image is broken)

1. **Build the Docker image locally**:
 ## see more at https://static.opendev.org/docs/kolla/latest/admin/image-building.html
   If the official image is broken or unavailable, you can build it locally. This example for  kolla-toolbox.

   ```bash
kolla-build -n quay.io/openstack.kolla --threads 8 --skip-existing --base ubuntu --tag yoga kolla-toolbox
   ```

2. **Verify the build**:

   After building the image, verify that it exists:

   ```bash
   docker images | grep kolla-toolbox
   ```

   - The expected output should be:
     ```bash
     kolla/ubuntu-source-kolla-toolbox   yoga   <image_id>
     ```

---

#### Step 2 **Re-tag (if needed)** [Do this on 5 hosts if you do] [I totally skipped this whole step]:

   If Kolla expects the `quay.io/...` format for the image, you can re-tag it:
   Usage:  docker tag SOURCE_IMAGE[:TAG] TARGET_IMAGE[:TAG]

   ```bash
   docker tag quay.io/openstack.kolla/ubuntu-source-kolla-toolbox:yoga kolla/ubuntu-source-kolla-toolbox:yoga
   ```
   Or alternatively, modify Kolla to use the `kolla/` namespace instead (depending on your preference or setup).
  
#### `retag_images.sh`
sudo nano retag_images.sh
#### add these lines to the file and save
```ini
#!/bin/bash

# Loop through all images with the 'yoga' tag and retag them to 'yoga-eol' in the kolla namespace
for image in $(docker images --format "{{.Repository}}:{{.Tag}}" | grep 'quay.io/openstack.kolla/ubuntu-source'); do
    # Retag the image to kolla namespace
    new_image="kolla/$(echo $image | cut -d/ -f2-)"
    docker tag $image $new_image
    echo "Retagged $image to $new_image"
done

# Verify the new tags
echo "Verifying the new tags..."
docker images | grep kolla/ubuntu-source

# Remove old images from quay.io/openstack.kolla namespace (duplicates)
for old_image in $(docker images --format "{{.Repository}}:{{.Tag}}" | grep 'quay.io/openstack.kolla/ubuntu-source'); do
    docker rmi -f $old_image
    echo "Removed old image: $old_image"
done

```
###Run the Script
```bash
sudo chmod +x retag_images.sh
./retag_images.sh
```

Verify:
```bash
   sudo docker image ls
#--> Results should show only "kolla/..." 
```

## Deploy Openstach use Kolla-ansible
# [Note]: If you are deploying `yoga` version, remember to take this step, or you will encounter error of restarting loop on "kolla_toolbox" container due to the "sudo" binary of the container image is not correctly set with permission required - which we have discussed right above (Check log: "docker logs --tail=50 kolla_toolbox" for more info). If you forget to do the [Manually built kolla-toolbox and Enter the image to inspect] step and got that error, then remove that image
```bash
docker stop kolla_toolbox
docker rm kolla_toolbox
```
# and try again from the "kolla-ansible pull" step.
# [Note end]

### Step 1. Re-configure `/etc/kolla/globals.yml` to Use Local Images

Edit the file:

```bash
sudo cp /etc/kolla/globals.yml /etc/kolla/globals.yml.1
sudo vi /etc/kolla/globals.yml
```

### ✅ Add or modify these entries

```yaml

docker_registry: ""
docker_registry_insecure: "no"
docker_namespace: "kolla"
```

---

## 🚀 4. Deploy with Kolla-Ansible Using Local Images

### ✅ Deploy

```bash
cd /etc/kolla/ansible/inventory/
source ~/kolla-venv/bin/activate
   
# Verify setting
ansible localhost -m setup | grep ansible_interfaces -A10

# Deploy openstack
sudo systemctl restart docker # I skipped this
sudo docker ps -q | xargs -r sudo docker stop # I skipped this too
kolla-ansible deploy -i /etc/kolla/ansible/inventory/multinode # Might need to run multiple time because some service might take long to boot up - which cause checking step failed.
```
# Sometime you will have to deal with annoying rabbitmq stuff
```bash
# Stop and remove the container
docker stop rabbitmq
docker rm rabbitmq

# Remove RabbitMQ data volume (this will reset all RabbitMQ data)
docker volume rm rabbitmq
```

# Generally, it things go wrong, run again with verbose option (-vvv) for debugging
```bash
##Debugs if some false
ansible-playbook \
  -i /etc/kolla/ansible/inventory/multinode \
  -e @/etc/kolla/globals.yml \
  -e @/etc/kolla/passwords.yml \
  -e kolla_action=deploy \
  /home/deployer/kolla-venv/share/kolla-ansible/ansible/site.yml -vvvv
###
```

### ✅ Post-Deployment

```bash
# Post-deploy 
kolla-ansible post-deploy -i /etc/kolla/ansible/inventory/multinode

# Generate openrc file
sudo cp /etc/kolla/admin-openrc.sh ~/
sudo chmod +r ~/admin-openrc.sh
source ~/admin-openrc.sh
```

### ✅ Verification and Troubleshooting

### Verify OpenStack Services

```bash
# Install OpenStack client
pip install python-openstackclient

# Run this to source cred when you 1st deploy openstack
source ~/kolla-venv/bin/activate
cd /etc/kolla/ansible/inventory/
sudo chown $USER:$USER /etc/kolla/admin-openrc.sh
sudo chmod +x /etc/kolla/admin-openrc.sh
source /etc/kolla/admin-openrc.sh

# Source credentials
sudo chmod +r /etc/kolla/admin-openrc.sh
source /etc/kolla/admin-openrc.sh

# List services
openstack service list

# --> results
(kolla-venv) deployer@aio:/etc/kolla/ansible/inventory$ openstack service list
+----------------------------------+-----------+----------------+
| ID                               | Name      | Type           |
+----------------------------------+-----------+----------------+
| 167b1bfaa270474fb531e609f5c6e04d | heat-cfn  | cloudformation |
| 233432e1eccb47b6bca1dd3198dcc1fe | heat      | orchestration  |
| 94f361407add48daaee550df5bb69d42 | placement | placement      |
| a012e0b90e0f42f39d876a3a5e198ce4 | neutron   | network        |
| b725a8863f1e41f4a06d5f5be76cedb0 | glance    | image          |
| d49480d67fd74b8ba63186481f22ca17 | keystone  | identity       |
| f8cf02cddc4f4507aa8e1a0fa3580827 | nova      | compute        |
+----------------------------------+-----------+----------------+

# List endpoints
openstack endpoint list

# --> results
(kolla-venv) deployer@aio00:/etc/kolla/ansible/inventory$ openstack endpoint list
+----------------------------------+-----------+--------------+----------------+---------+-----------+-------------------------------------+
| ID                               | Region    | Service Name | Service Type   | Enabled | Interface | URL                                 |
+----------------------------------+-----------+--------------+----------------+---------+-----------+-------------------------------------+
| 0be7c3d3da6e45ccb03dc42c4eb14802 | RegionOne | placement    | placement      | True    | public    | http://192.168.25.254:8780          |
| 25aba9ea87da4fb99a522dc720953847 | RegionOne | keystone     | identity       | True    | public    | http://192.168.25.254:5000          |
| 261b1a9fe0dd48c7a37e31016c938a06 | RegionOne | glance       | image          | True    | internal  | http://192.168.25.254:9292          |
| 356cae2647464742a8ef4a82977b5c2f | RegionOne | nova         | compute        | True    | public    | http://192.168.25.254:8774/v2.1     |
| 4783036bf55240cdb728386c002b271a | RegionOne | neutron      | network        | True    | internal  | http://192.168.25.254:9696          |
| 4d1c0eb6b5164b13a89bba2e6461e6aa | RegionOne | heat         | orchestration  | True    | public    | http://192.168.25.254:8004/v1/%(ten |
|                                  |           |              |                |         |           | ant_id)s                            |
| 4d6001eff56b4f9a830cafe5dc13b7b7 | RegionOne | keystone     | identity       | True    | internal  | http://192.168.25.254:5000          |
| 74955875edd94777b619df5e45ac2a23 | RegionOne | glance       | image          | True    | public    | http://192.168.25.254:9292          |
| 8f8892fe82cd49c6b98ce7adfb011cd5 | RegionOne | heat-cfn     | cloudformation | True    | internal  | http://192.168.25.254:8000/v1       |
| bf0e9c4dc3ef4122a21748d74c638571 | RegionOne | heat         | orchestration  | True    | internal  | http://192.168.25.254:8004/v1/%(ten |
|                                  |           |              |                |         |           | ant_id)s                            |
| c904c04d2a6e44709c170421c31b2115 | RegionOne | placement    | placement      | True    | internal  | http://192.168.25.254:8780          |
| cd267c54204d401fbaea4720b4c06a97 | RegionOne | nova         | compute        | True    | internal  | http://192.168.25.254:8774/v2.1     |
| d91f91cc19a148f292c5029398983714 | RegionOne | neutron      | network        | True    | public    | http://192.168.25.254:9696          |
| fb44da92f90c46c79cb75abe882a4aa9 | RegionOne | heat-cfn     | cloudformation | True    | public    | http://192.168.25.254:8000/v1       |
+----------------------------------+-----------+--------------+----------------+---------+-----------+-------------------------------------+


### ✅ Dashboard login
http://192.168.25.254
name: admin
#Check all password in `/etc/kolla/cat passwords.yml`
# Example for keystone
grep keystone_admin_password /etc/kolla/passwords.yml
# --> keystone_admin_password: y6pn3SnyvhsFilQyOrTAIuvZzzQR4MHesGuXJSNl

# [Successfully installed Openstack] if you reach this far!

### Troubleshooting Network Issues

If you encounter network connectivity issues:

1. **Check Bridge Status**:

   ```bash
   ip link show br0
   bridge link show
   ```

2. **Verify IP Forwarding**:

   ```bash
   cat /proc/sys/net/ipv4/ip_forward  # Should be 1
   ```

3. **Check NAT Rules**:

   ```bash
   sudo iptables -t nat -L -n -v
   ```

4. **Verify Routing**:

   ```bash
   ip route show
   ```

5. **Test with Traceroute**:

   ```bash
   # Install traceroute if needed
   sudo apt install traceroute -y
   
   # Test from namespace
   sudo ip netns exec testns traceroute 8.8.8.8
   ```

6. **Check Docker/Container Networking**:

   ```bash
   sudo docker network ls
   sudo docker ps
   ```

---
## 📝 Important Notes

1. **Bridge Layer 2 Nature**: Remember that bridges operate at Layer 2. You cannot directly ping external addresses from the bridge interface itself. Always test connectivity from a host (or namespace) connected to the bridge.

2. **Interface Names**: Replace `ens160` and other interface names with your actual interface names throughout this guide.

3. **IP Addresses**: Adjust IP addresses according to your network setup. Ensure the external VIP (`kolla_external_vip_address`) is an unused IP on your external network.

4. **OpenStack Version**: The guide uses "yoga" as the OpenStack release. Adjust this to your preferred version.

5. *Turn of all dotker running*
```bash
sudo docker ps -q | xargs -r sudo docker stop
```

6. Restart docker

```bash
sudo systemctl restart docker
```

7. Build openvswitch-db-server if deploy raise errors

```bash
sudo pip3 install kolla
sudo kolla-build openvswitch-db-server
sudo docker image rm quay.io/openstack.kolla/ubuntu-source-openvswitch-db-server

#Re deploy
kolla-ansible deploy -i ./multinode
```

### Monitoring / dashboard note:
# Hypervisor/Host cluster monitoring
http://192.168.25.254/admin/hypervisors/

------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------

# OpenStack Network, VM Deployment and SSH Access Guide
[Now we can create openstack "public" network with address 192.168.25.1/24 via "openstack network create ..." and "openstack subnet create ..."]. This is where Neutron allocates Floating IPs for VMs. I just note it here for reference. We will do it later on
On aio00 or any host with OpenStack CLI configured
```bash
openstack network create public1 \
  --external \
  --provider-network-type flat \
  --provider-physical-network physnet1 \
  --share

openstack subnet create public1-subnet \
  --network public1 \
  --subnet-range 192.168.25.0/24 \
  --gateway 192.168.25.1 \
  --no-dhcp \
  --allocation-pool start=192.168.25.150,end=192.168.25.199

# Try testing with the same net
openstack subnet create public1-subnet \
  --network public1 \
  --subnet-range 192.168.25.0/24 \
  --gateway 192.168.25.1 \
  --no-dhcp \
  --allocation-pool start=192.168.25.150,end=192.168.25.199
```
📌 Notes:
    - gateway: Matches aio0’s br-exnat IP
    - allocation-pool: Floating IPs Neutron assigns VMs (don’t overlap with aio0’s 192.168.25.1)
    - physnet1: Maps to neutron_external_interface: br-exnat

[Step 3:Create private network and router]
```bash
# If server got reboot, you need to create veth pair again (Section [Creating veth pair] note above), enable kernel module (Section [Enable kernel modules] above) + required flag like ip forwarding (Section [Enable require flag] nove above) and then run deploy + post-deploy one more time
# Run deploy, post-deploy again after reboot. Re-reploy does not clear all of the previous state and install from fresh. It just bring the service of all 5 hosts up. See more command on "kolla-ansible --help"
## The command "kolla-ansible deploy" will only
#   Detect already existing containers, configs, volumes
#   Only create/start containers that are missing or stopped
#   Apply updated configs if needed (but not wipe volumes)
## So it acts like a "resume":
#   ✔️ Starts services that aren't running
#   ✔️ Reconfigures them if necessary
#   ❌ Does NOT delete databases or volumes
#   ❌ Does NOT reinstall OpenStack from scratch
## Similarly, post-deploy only
#   Updates admin-openrc.sh
#   Registers OpenStack services in keystone
#   Sets up endpoints
## => So it's safe to rerun "deploy" and "post-deploy" and won't reset anything.
kolla-ansible deploy -i /etc/kolla/ansible/inventory/multinode
kolla-ansible post-deploy -i /etc/kolla/ansible/inventory/multinode

# You may potentially need to run "kolla-ansible mariadb_recovery -i /etc/kolla/ansible/inventory/multinode" or whatever failed when re-deploying
# If you got problem in this step, please refer to section [Debugging "mariadb recovery" for redeploying] section
```

[Housekeeping's done, here come the fun]
---

##2.  Create Network, Subnet, Router (Tenant & External)
```bash
# Activate OpenStack environment
source ~/kolla-venv/bin/activate
cd /etc/kolla/ansible/inventory/
source /etc/kolla/admin-openrc.sh

# Create internal tenant network [PRIVATE NETWORK, OR APP DOMAIN NETWORK. We name it "private-net"]
openstack network create private-net

# Create subnet in tenant network [Subnet for the private net]
openstack subnet create private-subnet \
  --network private-net \
  --subnet-range 10.0.0.0/24 \
  --gateway 10.0.0.1 \
  --dns-nameserver 8.8.8.8 \
  --allocation-pool start=10.0.0.100,end=10.0.0.200


# Create external (openstack "public" network) flat network (mapped directly [br0 with port[ens160]: 192.168.25.X]). This act as gateway for internal openstack VM to reach internet. Also this network is used for providing floating ip (192.168.25.X). We name this "public" network as "public1"
openstack network create public1 \
  --external \
  --provider-network-type flat \
  --provider-physical-network physnet1 \
  --share

#  Create subnet for openstack "public1" public network. Set gateway correctly within the subnet range (must match subnet. In our case, 192.168.25.1):
openstack subnet create public1-subnet \
  --network public1 \
  --subnet-range 192.168.25.0/24 \
  --gateway 192.168.25.1 \
  --no-dhcp \
  --allocation-pool start=192.168.25.150,end=192.168.25.199

# Create router
openstack router create router1

# Set external gateway to public1
openstack router set router1 --external-gateway public1

# Add private subnet to the router
openstack router add subnet router1 private-subnet


#Verify
openstack router show router1
#--> Results should show both ` 192.168.25.154` and `10.0.0.1`

# Verify
openstack router show router1 -c interfaces_info -c status

#--> Results should show '10.0.0.1`
```
---


## 🚀 5. Setup Virtual Machines (VMs)

- **Source Admin Credentials**
```bash
source ~/kolla-venv/bin/activate
cd /etc/kolla/ansible/inventory/
source /etc/kolla/admin-openrc.sh
```

---

- **Download VM Images and Upload a Cloud Image**
```bash
cd /etc/kolla/ansible/inventory/
### Download
sudo wget https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img -O ubuntu-focal.img
### Edit root password if needed (In case there're a problem with metadata server and/or somehow your openstack guest is not getting ssh key injected or network error so you cannot login into it via ssh. If so, a console password login would help troubleshooting)
sudo apt install guestfs-tools -y
sudo virt-customize -a ./ubuntu-focal.img  --root-password password:Password@123

#### Upload to cloud
openstack image create "Ubuntu-20.04" \
  --file ubuntu-focal.img \
  --disk-format qcow2 \
  --container-format bare \
  --public
```
[In my case, I use "Jammy" Ubuntu 22.04 image build: `wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img -O ubuntu-jammy-22.04.img`] 
[If you use this one, remember to also change the name of openstack image: `openstack image create "Ubuntu-22.04" --file ubuntu-jammy-22.04.img --disk-format qcow2 --container-format bare --public`]

- **Create a Flavor to run the VM images**
## Example:
```bash
openstack flavor create m1.small --ram 2048 --disk 10 --vcpus 1
```

## I got some recommendations from Google to build a k8s cluster
  # Small/Testing: 2 vCPUs, 4GB RAM, 20GB disk (for worker nodes)
  # Medium/Production: 4 vCPUs, 8GB RAM, 40GB disk (for worker nodes)
  # Large/Master Node: 8 vCPUs, 16GB RAM, 80GB disk (or more for larger clusters) 
# I guess I will go with the 3rd option but 8gb RAM, for both K8s Master + Worker
```bash
openstack flavor create m2.large --ram 8192 --disk 80 --vcpus 8
```

- **Create Security Group**
# Create `allow-ssh-ping` group - which got strict policy (ssh allow only)
```bash
# (If not already done)
openstack security group create allow-ssh-ping

# Allow ICMP (ping) INBOUND
openstack security group rule create --proto icmp --ingress allow-ssh-ping

# Allow SSH (port 22) INBOUND
openstack security group rule create --proto tcp --dst-port 22 --ingress allow-ssh-ping

# Allow all ICMP OUTBOUND (e.g. ping, traceroute)
openstack security group rule create --proto icmp --egress allow-ssh-ping

# Allow all TCP OUTBOUND (e.g. apt, curl)
openstack security group rule create --proto tcp --egress allow-ssh-ping

# Optionally: allow UDP (for DNS, etc.)
openstack security group rule create --proto udp --egress allow-ssh-ping

```
# Create `no-restriction` group - which got more laxed policy (allow all) - For debugging
```bash
# Create a new security group with no restrictions
openstack security group create no-restrictions

# Allow all traffic
openstack security group rule create --proto tcp --dst-port 1:65535 no-restrictions
openstack security group rule create --proto udp --dst-port 1:65535 no-restrictions
openstack security group rule create --proto icmp no-restrictions

openstack security group rule create --proto icmp --egress no-restrictions
openstack security group rule create --proto tcp --egress no-restrictions
```

# [Note]: Add or remove machine from security group
```bash
openstack server add security group <server> <security_group>
openstack server remove security group <server> <security_group>
# # Example
# openstack server add security group my-vm-small no-restrictions
# openstack server remove security group my-vm-small allow-ssh-ping
```

# [Note]: Checking security group and details
```bash
openstack security group list # To list security group
openstack security group show allow-ssh-ping # Examine the security group "allow-ssh-ping"
```

- **Create SSH Keypair**
**[Note]: You need to create ssh key as "ubuntu" user (I don't know why but we will have error as cloud-init failed to inject key somehow and even the ssh service failed to start - looks like it. Maybe because the image only have "ubuntu" user so if we inject ssh key as other user, it fails I guess)**
```bash
# Create dummy "ubuntu" user if you don't have any on the aio0
sudo useradd -m -s /bin/bash ubuntu
# Login as ubuntu
sudo su ubuntu
```
**Create keypair as "ubuntu" user**
```bash
# As "ubuntu" user, create keypair
ssh-keygen -t ecdsa -b 256 -f ~/.ssh/id_ecdsa -N ""
```

**Copy "ubuntu" keypair and take ownership for later usage to create openstack keypair**
```bash
sudo ls -la /home/ubuntu/
sudo ls -la /home/ubuntu/.ssh
sudo cp -r /home/ubuntu/.ssh ~/.ssh/ubuntu
sudo chown -R $USER:$USER  ~/.ssh/ubuntu
```

**Upload keypair to openstack for later use**
```bash
openstack keypair create mykey-ecc --public-key ~/.ssh/ubuntu/id_ecdsa.pub
```

# [Original guidance if you are running as "ubuntu" instead of "deployer"]
```bash
# Generate an ECC key using the NIST P-256 curve
ssh-keygen -t ecdsa -b 256 -f ~/.ssh/id_ecdsa -N ""
# Upload the public key to OpenStack:
openstack keypair create mykey-ecc --public-key ~/.ssh/id_ecdsa.pub

#Notes for usage later: 
# We create and check for floating IP via the later part: [Allocate & Associate Floating IP for VMs]. So technically we should do the later part 1st (create + boot up machine, assign floating IP) and then we can use this command to login
ssh -i ~/.ssh/id_ecdsa ubuntu@<floating-ip>
```
- **Launch the VM which asosiated with the SSH key `id_ecdsa.pub`** 
```bash
#Check the key pair
openstack keypair list

#Lanch VM machine [Remember to change the accordingly option with the flavor you created above]. Example:
openstack server create my-vm-small \
--flavor m1.small \
--image Ubuntu-20.04 \
--nic net-id=$(openstack network show private-net -f value -c id) \
--key-name mykey-ecc \
--security-group no-restrictions

# My version:
openstack server create my-vm \
--flavor m2.large \
--image Ubuntu-22.04 \
--nic net-id=$(openstack network show private-net -f value -c id) \
--key-name mykey-ecc \
--security-group allow-ssh-ping

#Verify
openstack server list
#Results should like `385a32d1-fa78-4b5c-95cd-ce5451d02c27 | my-vm | ACTIVE | private-net=10.0.0.198 | Ubuntu-20.04 | m1.small`
# If it is in the BUILD state, we should wait until it is in ACTIVE state
```
---

- **Allocate & Associate Floating IP for VMs**
```bash
# Allocate floating IP from public network
openstack floating ip create public1

# --> outputs need contens like: `floating_ip_address | 192.168.25.198  

# List floating IP
openstack floating ip list

# Associate it with your `my-vm` instance (above ouput IP)
openstack server add floating ip my-vm 192.168.25.198

#Verify
openstack server show my-vm -c addresses
#outputs show ` addresses | private-net=10.0.0.198, 192.168.25.198
```
---

## 🚀 6. Verify the network and connect to Machines (VMs) using SSH
```bash
chmod 600 ~/.ssh/id_ecdsa

# Check VM Status
openstack server list
openstack server show my-vm -c status -c addresses

# Confirm Floating IP Binding
openstack floating ip list --long
# --> shloud show Floating IP Address like: `192.168.25.198`

#Verify Router and External Network
openstack router show router1 -c interfaces_info -c external_gateway_info

#Verify
docker exec -u root -it openvswitch_vswitchd ovs-vsctl show
sudo iptables -t nat -L -n -v
sudo  iptables -L FORWARD -n -v
#. **Ping floating IP**
   ping -I br-ex 192.168.25.198  # Doesn't work
   ping 192.168.25.198          # Work
   ```
---

# SSH into guest via floating ip
```bash
ssh -i ~/.ssh/ubuntu/id_ecdsa ubuntu@192.168.25.198
```

# [MICS]: Trouble shooting
Try this from the hypervisor hosting the VM:
```bash
# Install if you don't have it
sudo apt install libvirt-clients -y
# Access the console
sudo virsh console <instance-id>

# If you get a login prompt, check:
ps aux | grep sshd
cat /home/ubuntu/.ssh/authorized_keys

# If there’s no sshd or no authorized_keys, it’s the image that cause the problem (cannot inject ssh key, maybe?).

# Also verify the cloud-init datasource:
sudo journalctl -u cloud-init
```
