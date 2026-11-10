# Reglas de ejemplo para MikroTik (RouterOS 7)

> **Son plantillas, no un script para pegar a ciegas.** Adáptalas (nombres de interfaces, listas, umbrales). Haz **respaldo antes** (`/system backup save` y `/export`), prueba primero con `log=yes` sin descartar, y revisa que no afecten a VoIP, juegos o clientes con tráfico legítimo alto. Las IP de ejemplo son de documentación (RFC 5737).

## 1. Detectar inundación UDP saliente por cliente

`dst-limit` coincide mientras el tráfico está **dentro** del límite. Para atrapar a quien lo **supera**, deja pasar lo normal con `return` y marca lo demás.

```routeros
/ip firewall raw
add chain=prerouting protocol=udp in-interface-list=LAN \
    dst-limit=500,100,src-address/1s action=return \
    comment="UDP dentro del limite (500 pps por cliente)"
add chain=prerouting protocol=udp in-interface-list=LAN \
    action=add-src-to-address-list address-list=UDP_FLOOD address-list-timeout=1h \
    log=yes log-prefix="UDP-FLOOD " \
    comment="UDP por encima del limite: marcar y registrar"
```

Empieza solo registrando. Mira `/log print where message~"UDP-FLOOD"` y `/ip firewall address-list print where list=UDP_FLOOD` durante unos días, ajusta el umbral y recién entonces decide si descartas.

## 2. Detectar barridos de puertos (SYN a muchos destinos)

```routeros
/ip firewall filter
add chain=forward protocol=tcp tcp-flags=syn,!ack in-interface-list=LAN \
    dst-limit=50,50,src-address/10s action=return comment="SYN normal"
add chain=forward protocol=tcp tcp-flags=syn,!ack in-interface-list=LAN \
    action=add-src-to-address-list address-list=Escaneo_Saliente address-list-timeout=1d \
    log=yes log-prefix="SCAN-OUT " comment="Barrido saliente"
```

Revisa quién cayó en la lista: `/ip firewall address-list print where list=Escaneo_Saliente`.

## 3. Bloquear servidores de control conocidos

```routeros
/ip firewall address-list
add list=BOTNET_C2 address=198.51.100.10 comment="servidor de control (ejemplo)"
/ip firewall raw
add chain=prerouting dst-address-list=BOTNET_C2 action=drop \
    log=yes log-prefix="C2-BOTNET " comment="Descartar y registrar C2"
```

Es una medida **parcial**: si el servidor cambia de IP, deja de servir. Lo útil es el log: te dice qué cliente está infectado.

## 4. Bloquear el servicio que abusa un cliente concreto

Ejemplo real: un cliente barría SIP (UDP 5060/5061) hacia miles de direcciones.

```routeros
/ip firewall raw
add chain=prerouting protocol=udp dst-port=5060,5061 src-address=10.0.0.40 \
    action=drop comment="Barrido SIP del cliente X (revisar y retirar)"
```

## 5. Buscar otros clientes con el mismo patrón

```routeros
/ip firewall connection print where dst-address=198.51.100.10
/ip firewall connection print count-only where src-address=10.0.0.40 protocol=udp
/ip arp print where mac-address~"^AA:BB:CC"        ;# mismo fabricante (OUI)
/tool torch interface=<LAN> src-address=10.0.0.40/32 port=any
```

Un cliente normal tiene decenas o pocos cientos de conexiones UDP; un bot en plena inundación, miles. Dentro de scripts de RouterOS usa `[:len [find ...]]`, no `print count-only`, porque este último imprime en vez de devolver el valor.

## Recordatorios

- Si compartes una IP pública entre muchos clientes (CG-NAT), un solo infectado puede ensuciar la reputación de todos.
- Mantén el puerto 25 saliente bloqueado para clientes residenciales, salvo excepciones.
- Documenta cada regla (comentario, fecha, motivo) y fija una fecha para retirarla.
