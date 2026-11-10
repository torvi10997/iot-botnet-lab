# Cómo capturar el tráfico de un dispositivo sospechoso

Objetivo: ver **todo** lo que el aparato envía y recibe, sin depender de que el router lo muestre. Usa solo equipos que sean tuyos o con permiso del dueño.

## Idea general

Pon tu PC en medio: el aparato se conecta a un punto de acceso que crea tu PC y tu PC sale a internet por otra interfaz. Wireshark/tshark ve todo el tráfico.

## Opción A: Windows con "Zona con cobertura inalámbrica móvil"

1. **Tu PC debe llegar a internet por cable** (Ethernet). Si sale por el mismo WiFi que va a compartir, Windows fuerza la banda 5 GHz y muchos TV box baratos solo ven 2,4 GHz.
2. Ajustes → Red e Internet → Zona con cobertura inalámbrica móvil: banda **2,4 GHz**, nombre y clave simples.
3. Conecta el aparato a ese WiFi. Comprueba que tiene IP (normalmente `192.168.137.x`).
4. Identifica la interfaz y captura:

```powershell
tshark -D                                   # lista de interfaces
tshark -i <n> -s 200 -w captura.pcapng -a duration:900
```

`-s 200` guarda solo los primeros 200 bytes de cada paquete (suficiente para las cabeceras y ocupa poco). **Ojo:** el número de interfaz puede cambiar entre ejecuciones; verifica con `tshark -D` o usa el identificador `\Device\NPF_{...}`.

5. Si capturas varios minutos con mucho tráfico, usa un buffer circular: `-b filesize:50000 -b files:20`.

## Opción B: Linux / Raspberry Pi como puente o AP

```bash
sudo tcpdump -i wlan0 -s 200 -w captura.pcap -G 900 -W 1
```

Con `hostapd` + `dnsmasq` + NAT haces lo mismo que la zona móvil de Windows.

## Opción C: puerto espejo (SPAN)

Si tu switch gestionable lo permite, refleja el puerto del cliente hacia tu PC y captura ahí.

## Buenas prácticas

- **Captura en reposo y en uso.** Pon el aparato en el menú principal 5 a 10 minutos y luego abre una app de video. Compara.
- **Filtra por MAC, no por IP**: la IP asignada puede cambiar al reconectar (`ether host aa:bb:cc:dd:ee:ff`).
- **Sin sorpresas**: si el aparato puede estar atacando, no dejes la captura sin vigilancia con internet real. Pon un corte automático (por ejemplo, desactivar el hotspot si supera 150 paquetes UDP por segundo en una ventana de 3 s) o limita el ancho de banda.
- **Prueba restablecido de fábrica**: repite la captura tras un reset para saber si el comportamiento desaparece.
- **Guarda la evidencia** (pcap, hora, MAC, versión de firmware) antes de cambiar nada.

## Después

```bash
python -m botnet_lab analyze captura.pcapng --device 192.168.137.50
```

Para confirmar a mano en Wireshark:

| Qué ver | Filtro de visualización |
|---|---|
| Inundación UDP | `udp && ip.src==192.168.137.50 && !dns` y Estadísticas → Conversaciones |
| Órdenes del servidor de control | `tcp && ip.dst==192.168.137.50 && tcp.len>0 && tcp.len<200` |
| DNS aleatorio | `dns.flags.response==0 && ip.dst!=192.168.137.1` |
| Barrido | `tcp.flags.syn==1 && tcp.flags.ack==0` |

Para saber **de quién es** una IP destino: `https://rdap.org/ip/<IP>` o `whois <IP>`.

Para ver puertos abiertos del aparato (en tu propia red): `nmap -sV -p 1-10000,5555 <IP>`. Un puerto **5555 (ADB) abierto y sin autenticación** es una puerta de entrada típica de estas botnets.
