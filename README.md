# FortiGate SNMP Dashboard

Dashboard web para monitoreo de dispositivos FortiGate mediante SNMP.

## Características

- Monitoreo de 29 dispositivos FortiGate (193.168.100.2-29, 193.168.100.250)
- Vista de resumen con estado general
- Pestañas por sucursal (hostname)
- Métricas: CPU, memoria, disco, sesiones activas, uptime
- Actualización automática cada 10 minutos vía cron
- Interfaz web responsiva con Bootstrap

## Requisitos

- Python 3
- pysnmp
- Flask
- snmpget (paquete snmp)
- Acceso SNMP a los FortiGates (comunidad: Agnov)

## Instalación

### En el servidor remoto:

```bash
# Clonar desde GitHub
git clone https://github.com/shinichikudo18/fortigate-dashboard.git /opt/fortigate-dashboard
cd /opt/fortigate-dashboard

# Instalar dependencias
pip3 install pysnmp flask --break-system-packages

# Configurar cron para recolección automática
crontab -e
# Agregar: */10 * * * * cd /opt/fortigate-dashboard && python3 scripts/snmp_collector.py >> /var/log/fortigate-collector.log 2>&1

# Iniciar dashboard
python3 scripts/dashboard.py
```

### Actualizar desde GitHub:

```bash
cd /opt/fortigate-dashboard
git pull origin master
```

## Uso

Acceder vía web: `http://<servidor>:8080`

## Estructura

```
fortigate-dashboard/
├── scripts/
│   ├── snmp_collector.py      # Recolector SNMP
│   ├── dashboard.py           # Servidor Flask
│   └── update_from_github.sh  # Script de actualización
├── templates/                 # Plantillas HTML
├── static/                    # CSS y JS
├── mibs/                      # Archivos MIB
└── data/                      # Datos JSON (generado)
```

## Licencia

MIT
