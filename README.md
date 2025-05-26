
# Курсовая работа на профессии "DevOps-инженер с нуля"
*Асадбеков Асадбек*

## Задача

Ключевая задача — разработать отказоустойчивую инфраструктуру для сайта, включающую мониторинг, сбор логов и резервное копирование основных данных. Инфраструктура должна размещаться в Yandex Cloud.

## Краткое описание

**Реализовано:**
- Балансировка и отказоустойчивость (ALB + 2 nginx)
- Мониторинг (Zabbix)
- PostgreSQL кластер (master+replica)
- Bastion host для защищенного доступа и NAT
- Сбор логов (Elasticsearch, Kibana, Filebeat)
- Автоматическое резервное копирование (snapshot lifecycle)

---

## 1. Архитектура и основные компоненты

- **Веб-сервера:** 2 ВМ с nginx в разных зонах.
- **Балансировщик (ALB):** распределение трафика, Target/Backend Group, healthcheck.
- **Zabbix Server** + агенты на web-нодах для мониторинга.
- **PostgreSQL master/replica:** отказоустойчивый кластер, NAT через bastion.
- **Bastion host:** защищенный SSH-доступ, NAT для приватных серверов.
- **ELK стек** (Elasticsearch, Kibana, Filebeat на docker): централизованный сбор и просмотр логов.
- **Резервное копирование:** автоматические снапшоты всех важных дисков, хранение 1 неделя.

---

## 2. Terraform: основная инфраструктура

### `main.tf`
```hcl
terraform {
  required_providers {
    yandex = {
      source  = "yandex-cloud/yandex"
      version = "~> 0.98"
    }
  }
}

provider "yandex" {
  service_account_key_file = "${path.module}/terraform-key.json"
  cloud_id                 = "b1gsj7sfde79kl5qkpbl"
  folder_id                = "b1gm0hnoge59gnkmh3dl"
  zone                     = "ru-central1-a"
}
```

### `network.tf`
```hcl
resource "yandex_vpc_network" "default" {
  name = "default-network"
}

resource "yandex_vpc_subnet" "public" {
  name           = "public-subnet-a"
  zone           = "ru-central1-a"
  network_id     = yandex_vpc_network.default.id
  v4_cidr_blocks = ["10.1.0.0/24"]
}

resource "yandex_vpc_subnet" "public_b" {
  name           = "public-subnet-b"
  zone           = "ru-central1-b"
  network_id     = yandex_vpc_network.default.id
  v4_cidr_blocks = ["10.2.0.0/24"]
}

resource "yandex_vpc_security_group" "web_servers" {
  name       = "web-servers-sg"
  network_id = yandex_vpc_network.default.id

  ingress {
    protocol          = "TCP"
    port              = 80
    predefined_target = "loadbalancer_healthchecks"
    description       = "ALB health checks"
  }

  ingress {
    protocol       = "TCP"
    port           = 80
    v4_cidr_blocks = ["0.0.0.0/0"]
    description    = "HTTP access"
  }

  ingress {
    protocol       = "TCP"
    port           = 22
    v4_cidr_blocks = ["0.0.0.0/0"]
    description    = "SSH access"
  }

  ingress {
    protocol       = "TCP"
    port           = 10051 
    v4_cidr_blocks = ["0.0.0.0/0"]
    description    = "Zabbix agent‑to‑server"
  }

  ingress {
    protocol       = "TCP"
    port           = 10050
    v4_cidr_blocks = ["10.1.0.0/24", "10.2.0.0/24"]
    description    = "Zabbix agent port"
  }

  egress {
    protocol       = "ANY"
    from_port      = 0
    to_port        = 65535
    v4_cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "yandex_vpc_security_group" "alb_access" {
  name       = "alb-access"
  network_id = yandex_vpc_network.default.id

  ingress {
    protocol          = "ANY"
    predefined_target = "loadbalancer_healthchecks"
    description       = "ALB health checks"
  }

  ingress {
    protocol       = "TCP"
    port           = 80
    v4_cidr_blocks = ["0.0.0.0/0"]
    description    = "Public HTTP access"
  }

  egress {
    protocol       = "TCP"
    port           = 80
    v4_cidr_blocks = ["10.1.0.0/24", "10.2.0.0/24"]
    description    = "To web servers"
  }
}

resource "yandex_vpc_gateway" "private_nat" {
  name = "private-nat-gateway"
}

resource "yandex_vpc_security_group" "db" {
  name       = "db-sg"
  network_id = yandex_vpc_network.default.id

  ingress {
    protocol       = "TCP"
    port           = 5432
    v4_cidr_blocks = ["10.1.0.0/24", "10.2.0.0/24"]
    description    = "PostgreSQL replication"
  }

  egress {
    protocol       = "ANY"
    from_port      = 0
    to_port        = 65535
    v4_cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "yandex_alb_target_group" "zbx_tg" {
  name = "zabbix-tg"
  target {
    subnet_id  = yandex_vpc_subnet.public.id 
    ip_address = "10.1.0.4"
  }
}

resource "yandex_alb_backend_group" "zbx_bg" {
  name = "zabbix-bg"

  http_backend {
    name             = "zabbix-http-backend"
    target_group_ids = [yandex_alb_target_group.zbx_tg.id]
    port             = 80
    weight           = 1

    healthcheck {
      timeout  = "1s"
      interval = "5s"

      http_healthcheck {
        path = "/zabbix"
      }
    }
  }
}

resource "yandex_vpc_subnet" "private_es" {
  name           = "private-es-subnet"
  zone           = "ru-central1-a"
  network_id     = yandex_vpc_network.default.id
  v4_cidr_blocks = ["10.3.0.0/24"]
}


resource "yandex_vpc_security_group" "es" {
  name       = "es-sg"
  network_id = yandex_vpc_network.default.id

  ingress {
    protocol       = "TCP"
    port           = 9200
    v4_cidr_blocks = ["10.1.0.4/32"] 
  }

  ingress {
    protocol       = "TCP"
    port           = 9300
    v4_cidr_blocks = ["10.3.0.0/24"]
  }

  ingress {
    protocol       = "TCP"
    port           = 22
    v4_cidr_blocks = ["10.10.1.11/32"] 
    description    = "SSH from bastion"

  }
  egress {
    protocol       = "ANY"
    v4_cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "yandex_vpc_security_group" "kibana" {
  name       = "kibana-sg"
  network_id = yandex_vpc_network.default.id

  ingress {
    protocol       = "TCP"
    port           = 5601
    v4_cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    protocol       = "TCP"
    port           = 9200
    v4_cidr_blocks = ["10.3.0.0/24"]
  }

  ingress {
    protocol       = "TCP"
    port           = 22
    v4_cidr_blocks = ["10.10.1.11/32"]
    description    = "SSH from bastion"
  }

  egress {
    protocol       = "ANY"
    v4_cidr_blocks = ["0.0.0.0/0"]
  }
}
```

### `vm-web.tf`
```hcl
vm-web.tf
resource "yandex_compute_instance" "web_1" {
  name                      = "web-instance-1"
  zone                      = "ru-central1-a"
  platform_id               = "standard-v1"
  allow_stopping_for_update = true

  resources {
    cores         = 2
    memory        = 2
    core_fraction = 20
  }

  boot_disk {
    initialize_params {
      image_id = var.image_id
    }
  }

  network_interface {
    subnet_id          = yandex_vpc_subnet.public.id
    nat                = false
    security_group_ids = [yandex_vpc_security_group.web_servers.id]
  }

  metadata = {
    ssh-keys  = "asad:${file(var.ssh_key_path)}"
    user-data = file("cloud.init/web.init.yaml")
  }
}

resource "yandex_compute_instance" "web_2" {
  name                      = "web-instance-2"
  zone                      = "ru-central1-b"
  platform_id               = "standard-v1"
  allow_stopping_for_update = true

  resources {
    cores         = 2
    memory        = 2
    core_fraction = 20
  }

  boot_disk {
    initialize_params {
      image_id = var.image_id
    }
  }

  network_interface {
    subnet_id          = yandex_vpc_subnet.public_b.id
    nat                = false
    security_group_ids = [yandex_vpc_security_group.web_servers.id]
  }

  metadata = {
    ssh-keys  = "asad:${file(var.ssh_key_path)}"
    user-data = file("cloud.init/web.init.yaml")
  }
}
```

### `load-balancer.tf`
```hcl
resource "yandex_alb_target_group" "web_targets" {
  name = "web-target-group"

  target {
    subnet_id  = yandex_vpc_subnet.public.id
    ip_address = yandex_compute_instance.web_1.network_interface.0.ip_address
  }

  target {
    subnet_id  = yandex_vpc_subnet.public_b.id
    ip_address = yandex_compute_instance.web_2.network_interface.0.ip_address
  }
}
```

### `vm-elk.tf`
```hcl
resource "yandex_compute_instance" "elastic" {
  name        = "elastic-vm"
  zone        = "ru-central1-a"
  platform_id = "standard-v1"

  resources {
    cores         = 2
    memory        = 4
    core_fraction = 20
  }

  boot_disk {
    initialize_params {
      image_id = "fd83m7rp3r4l12c2keph" 
      size     = 20
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.private_es.id
    security_group_ids = [yandex_vpc_security_group.es.id] 
    nat       = false
  }

  metadata = {
    ssh-keys = "yc-user:${file("~/.ssh/id_rsa.pub")}"
  }

  scheduling_policy {
    preemptible = true
  }
}

resource "yandex_compute_instance" "kibana" {
  name        = "kibana-vm"
  zone        = "ru-central1-a"
  platform_id = "standard-v1"

  resources {
    cores         = 2
    memory        = 2
    core_fraction = 20
  }

  boot_disk {
    initialize_params {
      image_id = "fd83m7rp3r4l12c2keph" 
      size     = 15
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.private_es.id
    security_group_ids = [yandex_vpc_security_group.kibana.id] 
    nat       = false
  }

  metadata = {
    ssh-keys = "yc-user:${file("~/.ssh/id_rsa.pub")}"
  }

  scheduling_policy {
    preemptible = true
  }
}
```

### `bastion.tf`
```hcl
resource "yandex_vpc_subnet" "subnet_a" {
  name           = "asad-subnet-a"
  zone           = var.zone_a
  network_id     = yandex_vpc_network.default.id
  v4_cidr_blocks = ["10.10.1.0/24"]
}

resource "yandex_vpc_subnet" "subnet_b" {
  name           = "asad-subnet-b"
  zone           = var.zone_b
  network_id     = yandex_vpc_network.default.id
  v4_cidr_blocks = ["10.10.2.0/24"]
}

resource "yandex_vpc_security_group" "ssh_access" {
  name       = "ssh-access"
  network_id = yandex_vpc_network.default.id

  ingress {
    protocol       = "TCP"
    port           = 22
    v4_cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    protocol       = "ANY"
    from_port      = 0
    to_port        = 65535
    v4_cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "yandex_compute_instance" "bastion" {
  name        = "asad-bastion"
  zone        = var.zone_a
  platform_id = "standard-v1"

  allow_stopping_for_update = true

  resources {
    cores         = 2
    memory        = 2
    core_fraction = 20
  }

  boot_disk {
    initialize_params {
      image_id = var.image_id
    }
  }

  network_interface {
    subnet_id          = yandex_vpc_subnet.subnet_a.id
    nat                = true
    security_group_ids = [yandex_vpc_security_group.ssh_access.id]
  }

  metadata = {
    ssh-keys = "ubuntu:${file(var.ssh_key_path)}"
  }
}
```

### `outputs.tf`
```hcl
output "web_instance_1_ip" {
  value = yandex_compute_instance.web_1.network_interface.0.ip_address
}

output "web_instance_2_ip" {
  value = yandex_compute_instance.web_2.network_interface.0.ip_address
}

output "alb_external_ip" {
  value = yandex_alb_load_balancer.web_lb.listener[0].endpoint[0].address[0].external_ipv4_address[0].address
}

output "bastion_ip" {
  description = "Public IP of bastion host"
  value       = yandex_compute_instance.bastion.network_interface[0].nat_ip_address
}

output "zabbix_internal_ip" {
  value = yandex_compute_instance.zabbix.network_interface[0].ip_address
}

output "pg_master_ip" {
  value = yandex_compute_instance.postgres_master.network_interface[0].ip_address
}

output "pg_replica_ip" {
  value = yandex_compute_instance.postgres_replica.network_interface[0].ip_address
}

output "elastic_ip" {
  value = yandex_compute_instance.elastic.network_interface.0.ip_address
}

output "kibana_ip" {
  value = yandex_compute_instance.kibana.network_interface.0.ip_address
}
```

### `terraform.tfvars`
```hcl
folder_id           = "b1gm0hnoge59gnkmh3dl"
opensearch_password = "StrongSecurePassword123!"
```

### `variables.tf`
```hcl
variable "zone_a" {
  default = "ru-central1-a"
}

variable "zone_b" {
  default = "ru-central1-b"
}

variable "image_id" {
  type    = string
  default = "fd8vmcue7aajpmeo39kk" 
}

variable "ssh_key_path" {
  type    = string
  default = "~/.ssh/id_rsa.pub"
}

variable "folder_id" {
  description = "ID папки Yandex Cloud, в которой создаются ресурсы"
  type        = string
}

variable "opensearch_password" {
  type      = string
  sensitive = true
}
```

---

## 3. Ansible

### `inventory.ini`
```ini
[bastion]
158.160.61.212 ansible_user=ubuntu ansible_ssh_common_args=''

[all:vars]
ansible_user=ubuntu
ansible_python_interpreter=/usr/bin/python3
ansible_ssh_private_key_file=~/.ssh/id_rsa
ansible_ssh_common_args='-o ProxyJump=ubuntu@158.160.61.212 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

[postgres_master]
10.1.0.9

[postgres_replica]
10.2.0.37

[zabbix_server]
10.1.0.4

[web_servers]
10.1.0.11
10.2.0.18

[postgres:children]
postgres_master
postgres_replica

[elasticsearch]
10.3.0.25 ansible_user=ubuntu

[elasticsearch:vars]
elastic_version=7.17.13
ansible_ssh_common_args='-o ProxyJump=ubuntu@158.160.61.212'

[kibana]
10.3.0.9 ansible_user=ubuntu
ansible_ssh_common_args='-o ProxyJump=ubuntu@158.160.61.212'

[elk:children]
elastic
kibana 
```

### `playbook_zabbix_server.yml`
```yaml
- name: Deploy Zabbix Server + Web on Ubuntu
  hosts: zabbix_server
  become: yes
  vars:
    db_host: 10.1.0.9
    db_name: zabbix
    db_user: zabbix
    db_password: zabbixpass
    zabbix_version: "6.4"

  pre_tasks:
    - name: Install prerequisites
      apt:
        name:
          - acl
          - gnupg
          - curl
          - python3-psycopg2
        state: present
        update_cache: yes

    - name: Import Zabbix GPG key
      apt_key:
        url: https://repo.zabbix.com/zabbix-official-repo.key
        state: present

    - name: Add Zabbix apt repo
      apt_repository:
        repo: "deb https://repo.zabbix.com/zabbix/{{ zabbix_version }}/ubuntu focal main"
        state: present
        filename: "zabbix"

  tasks:
    - name: Install Zabbix server stack
      apt:
        name:
          - zabbix-server-pgsql
          - zabbix-frontend-php
          - zabbix-apache-conf
          - zabbix-agent
        state: present
        update_cache: yes

    - name: Install PostgreSQL client and Zabbix SQL scripts
      apt:
        name:
          - postgresql-client
          - zabbix-sql-scripts
        state: present
        update_cache: yes

    - name: Import initial Zabbix schema (once)
      shell: |
        zcat /usr/share/zabbix-sql-scripts/postgresql/server.sql.gz | \
        PGPASSWORD="{{ db_password }}" psql -h {{ db_host }} -U {{ db_user }} {{ db_name }}
      args:
        creates: /var/lib/zabbix/.schema_done
      environment:
        PGPASSWORD: "{{ db_password }}"
      notify: restart zabbix

    - name: Configure DB connection
      lineinfile:
        path: /etc/zabbix/zabbix_server.conf
        regexp: '^{{ item.key }}='
        line: "{{ item.key }}={{ item.value }}"
      loop:
        - { key: DBHost,     value: "{{ db_host }}" }
        - { key: DBName,     value: "{{ db_name }}" }
        - { key: DBUser,     value: "{{ db_user }}" }
        - { key: DBPassword, value: "{{ db_password }}" }
      notify: restart zabbix
     
    - name: Allow unsupported PostgreSQL versions
      lineinfile:
        path: /etc/zabbix/zabbix_server.conf
        regexp: '^#?AllowUnsupportedDBVersions='
        line: 'AllowUnsupportedDBVersions=1'
      notify: restart zabbix

    - name: Set PHP timezone
      lineinfile:
        path: /etc/zabbix/apache.conf
        regexp: '^\s*php_value date.timezone'
        line: '        php_value date.timezone Europe/Moscow'
      notify: restart apache

  handlers:
    - name: restart zabbix
      service:
        name: zabbix-server
        state: restarted
        enabled: yes

    - name: restart apache
      service:
        name: apache2
        state: restarted
        enabled: yes
```

### `playbook_zabbix_agent.yml`
```yaml
- name: Install and configure Zabbix Agent on web servers
  hosts: web_servers
  become: yes
  vars:
    zabbix_server_ip: 10.1.0.4      
    zabbix_version: "6.4"           

  pre_tasks:
    - name: Ensure prerequisites are installed
      apt:
        name:
          - gnupg
          - curl
        state: present
        update_cache: yes

    - name: Import Zabbix GPG key
      apt_key:
        url: https://repo.zabbix.com/zabbix-official-repo.key
        state: present

    - name: Add Zabbix apt repository
      apt_repository:
        repo: "deb https://repo.zabbix.com/zabbix/{{ zabbix_version }}/ubuntu focal main"
        state: present
        filename: zabbix

  tasks:
    - name: Install Zabbix Agent
      apt:
        name: zabbix-agent
        state: present
        update_cache: yes

    - name: Configure Zabbix Agent to point to server
      lineinfile:
        path: /etc/zabbix/zabbix_agentd.conf
        regexp: '^Server='
        line: "Server={{ zabbix_server_ip }}"
      notify: restart zabbix-agent

    - name: Ensure agent listens on all interfaces
      lineinfile:
        path: /etc/zabbix/zabbix_agentd.conf
        regexp: '^ListenIP='
        line: 'ListenIP=0.0.0.0'
      notify: restart zabbix-agent

    - name: Start and enable Zabbix Agent service
      service:
        name: zabbix-agent
        state: started
        enabled: yes

  handlers:
    - name: restart zabbix-agent
      service:
        name: zabbix-agent
        state: restarted

```

### `playbook_filebeat.yml`
```yaml
- name: Install and configure Filebeat on web servers
  hosts: web_servers
  become: yes
  vars:
    es_ip: "{{ hostvars[groups.elasticsearch[0]].ansible_host }}"

  tasks:
    - name: Install Filebeat
      apt:
        name: filebeat
        state: present
        update_cache: yes

    - name: Configure Filebeat inputs and output
      copy:
        dest: /etc/filebeat/filebeat.yml
        content: |
          filebeat.inputs:
          - type: log
            paths:
              - /var/log/nginx/access.log
              - /var/log/nginx/error.log
          output.elasticsearch:
            hosts: ["http://{{ es_ip }}:9200"]

    - name: Enable and start Filebeat
      service:
        name: filebeat
        state: started
        enabled: yes

```

### `playbook_clear_elk.yml`
```yaml
---
---
- name: Полная очистка старого Elasticsearch и Docker
  hosts: elasticsearch
  become: yes

  tasks:
    - name: Остановить elasticsearch если запущен
      systemd:
        name: elasticsearch
        state: stopped
      ignore_errors: yes

    - name: Удалить пакеты elasticsearch и docker
      apt:
        name:
          - elasticsearch
          - docker-ce
          - docker-ce-cli
          - containerd.io
        state: absent
        purge: yes
      ignore_errors: yes

    - name: Удалить каталоги elasticsearch
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /var/lib/elasticsearch
        - /usr/share/elasticsearch
        - /etc/elasticsearch
        - /etc/default/elasticsearch
        - /etc/systemd/system/elasticsearch.service

    - name: Автоматическая очистка лишних пакетов
      apt:
        autoremove: yes
        purge: yes
        state: latest

    - name: Обновить кэш apt
      apt:
        update_cache: yes
```

---

## 4. Docker и конфиги ELK

### `docker-compose.yml` для Elasticsearch
```yaml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.13.0
    container_name: elasticsearch
    environment:
      - node.name=es01
      - discovery.type=single-node
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=1-2-3
    ports:
      - "9200:9200"
      - "9300:9300"
    volumes:
      - esdata:/usr/share/elasticsearch/data

volumes:
  esdata:
```

### `docker-compose.yml` для Kibana
```yaml
version: '3.8'

services:
  kibana:
    image: docker.elastic.co/kibana/kibana:8.13.0
    container_name: kibana
    environment:
      - SERVER_HOST=0.0.0.0
      - ELASTICSEARCH_HOSTS=http://10.3.0.25:9200
      - ELASTICSEARCH_SERVICEACCOUNTTOKEN=AAEAAWVsYXN0aWMva2liYW5hL215LWtpYmFuYS10b2tlbjp3cS1hZjVRLVR6Ml8xRmVtLVZtdllB
    ports:
      - "5601:5601"
```

### `filebeat.yml`
```yaml
filebeat.inputs:
  - type: filestream
    id: nginx-logs
    enabled: true
    paths:
      - /var/log/nginx/access.log
      - /var/log/nginx/error.log
    parsers:
      - ndjson: {}

output.elasticsearch:
  hosts: ["http://10.3.0.25:9200"]
  api_key: "ZE8wApcBQvNq1GTz6sq-:CB11CkLbT_KLAWm2OGv9EA"
```

### `kibana.yml`
```yaml
server.host: "0.0.0.0"

elasticsearch.hosts: ["https://10.3.0.25:9200"]
elasticsearch.serviceToken: "AAEAAWVsYXN0aWMva2liYW5hL215LWtpYmFuYS10b2tlbjp3cS1hZjVRLVR6Ml8xRmVtLVZtdllB"

# elasticsearch.username: "elastic"
# elasticsearch.password: "1-2-3"
```

---

## 5. Скриншоты

### Задание 1-2
![Docker Compose и запуск](https://github.com/asad-bekov/hw-21/raw/main/img/1.png)
![Проверка подключения к БД](https://github.com/asad-bekov/hw-21/raw/main/img/1.1.png)

### Задание 3
![Состояние контейнеров](https://github.com/asad-bekov/hw-21/raw/main/img/2.png)
![Ответ сервиса](https://github.com/asad-bekov/hw-21/raw/main/img/2.1.png)

### Задание 4
![Доступ через внешний IP](https://github.com/asad-bekov/hw-21/raw/main/img/3.png)
![SQL-результат запроса](https://github.com/asad-bekov/hw-21/raw/main/img/3.1.png)

### Задание 5
![Резервные копии в директории /opt/backup](https://github.com/asad-bekov/hw-21/raw/main/img/4.png)

### Задание 6
![Извлечение Terraform](https://github.com/asad-bekov/hw-21/raw/main/img/5.png)
![Проверка terraform version](https://github.com/asad-bekov/hw-21/raw/main/img/6.png)

### Задание 7
![Запуск runC-контейнера](https://github.com/asad-bekov/hw-21/raw/main/img/7.png)
![Ответ от Flask-приложения](https://github.com/asad-bekov/hw-21/raw/main/img/8.png)

---

## 6. Итог

- Вся инфраструктура полностью автоматизирована и описана кодом (Infrastructure as Code).
- Проверена отказоустойчивость, мониторинг, сбор логов, резервное копирование, безопасность доступа через bastion.
- Проект соответствует требованиям курсовой работы.

---
