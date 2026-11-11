# Plan de respuesta: encontré un dispositivo comprometido

## 1. Confirma (sin romper nada)

1. Identifica el equipo: IP, MAC, fabricante (los primeros 3 bytes de la MAC, "OUI").
2. Captura su tráfico en reposo y en uso (ver [CAPTURA.md](CAPTURA.md)) y analízalo con `python -m botnet_lab analyze`.
3. Busca la combinación: **latido + orden + inundación**. Una sola señal suele ser falso positivo.
4. Anota cuándo, qué destinos y cuánto tráfico. Guarda el pcap.

## 2. Contén

- Lo mínimo: sácalo de internet (red de invitados sin salida, regla de firewall, o desconectarlo).
- En un ISP: marca la IP del cliente en una lista, bloquea solo el servicio abusado (por ejemplo, UDP saliente) y registra, en vez de cortar todo el servicio, mientras no responda.
- No borres evidencia antes de guardarla.

## 3. Comunica

Mensaje corto al cliente, sin tecnicismos:

> Detectamos que uno de los dispositivos de su red (probablemente el TV box) está enviando tráfico anormal a internet, como si estuviera infectado. Le recomendamos desconectarlo y usar uno de marca certificada (Google TV, Fire TV, Apple TV). Si desea, le ayudamos a revisarlo.

Si no responde: fija un plazo escrito (48 a 72 horas) y aplica una suspensión temporal solo si reincide.

## 4. Remedia

- Restablecer de fábrica **no garantiza** que quede limpio (el firmware puede venir infectado de origen). Lo seguro es reemplazarlo.
- Apagar la depuración USB/inalámbrica (ADB), cambiar claves por defecto, actualizar el firmware del router, desactivar UPnP.
- Revisar el resto de la red del cliente (teléfonos, otras cajas, cámaras).

## 5. Vigila

- Siete días de seguimiento del cliente (log del firewall, conexiones UDP, contactos al servidor de control).
- Busca otros clientes con el mismo fabricante o el mismo destino.
- Retira las reglas temporales cuando el caso se cierre.

## 6. Reporta (opcional, ayuda a otros)

- Al operador del servidor de control (RDAP/whois de la IP, contacto de *abuse*), con hora, puerto y un extracto de la captura.
- Al CSIRT/CERT de tu país.
- Si compartes el caso públicamente: **sin nombres de clientes, IP ni MAC reales**.
