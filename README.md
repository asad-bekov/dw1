# Курсовая работа на профессии "DevOps-инженер с нуля"

*Асадбеков Асадбек* 
*29.04.2025*

## Что уже сделано:

### Инфраструктура (Terraform)
Развернута базовая инфраструктура в Yandex Cloud в двух зонах доступности (`ru-central1-a`, `ru-central1-b`):

- VPC + 2 сабсети
- Security Groups:
  - SSH
  - HTTP/HTTPS
  - Zabbix agents
  - ALB и health checks
- Bastion-хост: `158.160.114.222` (с публичным IP)
- Виртуальные машины:
  - `Zabbix-сервер`: `10.1.0.4`
  - `PostgreSQL Master`: `10.1.0.9`
  - `PostgreSQL Replica`: `10.2.0.8`
  - `Web-серверы`: `10.1.0.11`, `10.2.0.18` (Nginx)
  - `ALB`: `84.201.169.224` (распределяет трафик на web-сервера)
  - `Elasticsearch`: `10.3.0.33`
  - `Kibana`: `10.1.0.20`

### Настройка мониторинга (Ansible)

#### Zabbix
- Установлен Zabbix server
- Подключён к кластеру PostgreSQL
- Настроен frontend (HTTP) и агенты
- Развернут Zabbix Agent на web-1 и web-2
- Все роли оформлены через Ansible

#### PostgreSQL
- Установлен кластер PostgreSQL
- Настроена master-replica репликация
- Создан пользователь и база данных `zabbix`

#### Elasticsearch + Kibana
- Elasticsearch установлен вручную с .deb пакета с зеркала Yandex
- Kibana установлена из зеркала Yandex и настроена на подключение к Elasticsearch через `serviceAccountToken`

## Проблема

Kibana не может подключиться к Elasticsearch:
> `Unable to retrieve version information from Elasticsearch nodes. Request timed out`

Проблема в том, что **доступ к Elasticsearch блокируется в РФ**, и Kibana не может связаться с ним даже внутри ВМ.

---

## Вопрос

Могу ли я использовать вместо Elasticsearch — **OpenSearch** в Yandex.Cloud? YC поддержка предлагает такой вариант.
Если да — возможен ли перенос текущей конфигурации логирования и мониторинга на него?

---

## Что ещё предстоит:

-  Настройка Filebeat на web-1 и web-2 (для отправки логов в ELK)
-  Настройка HTTPS + TLS-сертификатов:
  - Zabbix frontend
  - Kibana
-  Настройка резервного копирования:
  - Бэкапы PostgreSQL
  - Снапшоты дисков через Yandex.Cloud API


## Ansible Playbook: Elasticsearch

```yaml
---
- name: Установка Elasticsearch через зеркало Яндекса
  hosts: elasticsearch
  become: yes

  tasks:
    - name: Добавить зеркало Яндекса
      shell: |
        echo "deb [trusted=yes] https://mirror.yandex.ru/mirrors/elastic/8/ stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
      args:
        executable: /bin/bash

    - name: Установка Java и Elasticsearch
      apt:
        name:
          - openjdk-17-jdk
          - elasticsearch
        state: present
        update_cache: yes

    - name: Установить vm.max_map_count
      sysctl:
        name: vm.max_map_count
        value: "262144"
        state: present
        reload: yes

    - name: Настроить network.host
      lineinfile:
        path: /etc/elasticsearch/elasticsearch.yml
        regexp: '^#?network.host:'
        line: 'network.host: 0.0.0.0'
        backup: yes

    - name: Убедиться, что сервис Elasticsearch запущен
      systemd:
        name: elasticsearch
        enabled: yes
        state: restarted

```

## Ansible Playbook: Kibana

```yaml
---
- name: Install and configure Kibana via Yandex mirror
  hosts: kibana
  become: yes

  vars:
    es_url: "https://10.3.0.33:9200"
    sa_token: "AAEAAWVsYXN0aWMva2liYW5hL2tpYmFuYS1zYTo1c243Q1dWRFFqdVpySTQ0MWE5alZ3"

  tasks:
    - name: Ensure no duplicate Elastic repo entries
      shell: |
        grep -v 'mirror.yandex.ru/mirrors/elastic' /etc/apt/sources.list | sudo tee /etc/apt/sources.list
        rm -f /etc/apt/sources.list.d/elastic-8.x.list
        rm -f /etc/apt/sources.list.d/elastic.list
      ignore_errors: yes

    - name: Manually add Yandex Elastic mirror to sources.list.d
      lineinfile:
        path: /etc/apt/sources.list.d/elastic-8.x.list
        line: "deb [trusted=yes] https://mirror.yandex.ru/mirrors/elastic/8 stable main"
        create: yes

    - name: Update apt cache
      apt:
        update_cache: yes

    - name: Install / upgrade Kibana
      apt:
        name: kibana
        state: latest
      notify: restart kibana

    - name: Configure /etc/kibana/kibana.yml
      blockinfile:
        path: /etc/kibana/kibana.yml
        create: yes
        marker: "# {mark} ANSIBLE MANAGED"
        block: |
          server.host: "0.0.0.0"
          server.ssl.enabled: false
          elasticsearch.hosts: ["{{ es_url }}"]
          elasticsearch.serviceAccountToken: "{{ sa_token }}"
      notify: restart kibana

  handlers:
    - name: restart kibana
      service:
        name: kibana
        state: restarted
        enabled: yes

```

## Пример Ansible inventory

```ini
[bastion]
158.160.114.222 ansible_user=ubuntu

[all:vars]
ansible_user=ubuntu
ansible_python_interpreter=/usr/bin/python3
ansible_ssh_private_key_file=~/.ssh/id_rsa
ansible_ssh_common_args='-o ProxyJump=ubuntu@158.160.114.222'

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
10.3.0.33 ansible_user=ubuntu

[elasticsearch:vars]
elastic_version=7.17.13
ansible_ssh_common_args='-o ProxyJump=ubuntu@158.160.114.222'

[kibana]
10.1.0.20 ansible_user=ubuntu
```
