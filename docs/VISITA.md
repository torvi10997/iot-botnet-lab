# Guía del técnico: revisar un aparato en casa del cliente

Para visitas donde se sospecha de un TV box, cámara u otro aparato (por ejemplo, tras un aviso de escaneos o ataques desde la IP del cliente).

## Qué necesitas

- Una laptop con **Windows**, WiFi y puerto **Ethernet** (o un adaptador USB-Ethernet).
- **Python 3.8+** y **Wireshark** instalado con la opción **TShark** marcada.
- Un cable de red para conectar la laptop al router del cliente (o a tu propia conexión).
- Permisos de administrador en la laptop para capturar.

## Antes de empezar: avisa al cliente

> Vamos a conectar su aparato a nuestra laptop durante unos 15 minutos para observar con quién se comunica. **Solo revisamos el tráfico de ese aparato**, no leemos su contenido personal, y la captura se borra al terminar. ¿Está de acuerdo?

Si el cliente no está de acuerdo, no captures. Guarda un registro de que se le avisó.

## Paso a paso

1. **Internet por cable.** La laptop debe llegar a internet por Ethernet. Si sale por el mismo WiFi que va a compartir, Windows fuerza 5 GHz y muchos TV box baratos no lo ven.
2. **Activa el hotspot:** Configuración, Red e Internet, *Zona con cobertura inalámbrica móvil*. Banda **2,4 GHz**, nombre y clave sencillos.
3. **Conecta el aparato** a ese WiFi y comprueba que recibió IP (normalmente `192.168.137.x`).
4. **Pon el aparato en uso**: por ejemplo, abre una app de video. Los bots a veces atacan solo con el aparato activo.
5. **Ejecuta el asistente** (en una terminal como administrador):

   ```
   python -m botnet_lab visita --minutos 15 --referencia "Casa de ..." --tecnico "Tu nombre"
   ```

   El asistente detecta solo el hotspot de Windows, te pide la MAC del aparato (opcional, pero recomendada: así solo se captura ese equipo) y captura.
6. **Lee el semáforo** (ver abajo) y entrega al cliente el informe HTML generado en la carpeta `informes`. Se puede imprimir o enviar por correo.
7. **Apaga el hotspot** y deja la red del cliente como estaba.

## Cómo leer el resultado

| Semáforo | Significa | Qué hacer |
|---|---|---|
| **Rojo** | Señales claras: inundación UDP, órdenes de un servidor de control, etc. | Desconectar el aparato, pedir reemplazo, informar al cliente |
| **Amarillo** | Hay señales que conviene revisar | Repetir 15 minutos o más con el aparato en uso y confirmar los destinos |
| **Verde** | No se vieron señales en la captura | No es garantía; recomendar equipos certificados |
| **No concluyente** | Captura menor de 10 minutos o el aparato casi no generó tráfico | Repetir; revisar MAC e interfaz |

**Un verde no es una garantía.** Un aparato infectado puede estar callado un buen rato. Por eso la herramienta nunca declara verde con menos de 10 minutos de captura.

## Si el aparato empieza a atacar

Mientras captura, el asistente revisa cada 20 segundos. Si ve una inundación sostenida, **detiene la captura y te pide desconectar el aparato de internet**. Hazlo de inmediato: desconecta el cable de la laptop, o desactiva el hotspot.

## Opciones útiles

```
--mac aa:bb:cc:dd:ee:ff   captura solo ese aparato
--guardar                 conserva la captura como evidencia (por defecto se borra)
--interfaz <id>           si no detecta el hotspot (ver `tshark -D`)
--desde-captura a.pcap    no captura: genera el informe de una captura existente
```

## Evidencia y privacidad

- Por defecto la captura **se borra**; solo queda el informe.
- Si guardas la captura como evidencia (`--guardar`), contiene IP, MAC y tráfico del cliente. Trátala como dato sensible, no la compartas ni la subas a repositorios públicos.
- Si publicas el caso, hazlo sin IP, MAC ni datos del cliente.

## Después de la visita

Sigue el [plan de respuesta](RESPUESTA.md): contención, comunicación al cliente, vigilancia durante siete días y, si aplica, reglas en el router del operador ([MikroTik](MIKROTIK.md)).
