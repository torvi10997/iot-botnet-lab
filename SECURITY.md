# Política de seguridad

## Cómo reportar una vulnerabilidad

**No abras un *issue* público** con los detalles de una vulnerabilidad.

1. En la página del repositorio, entra a la pestaña **Security** y pulsa **Report a vulnerability** (reporte privado).
2. Incluye qué encontraste, cómo reproducirlo y qué impacto crees que tiene. Si es posible, una captura o un archivo mínimo que lo muestre, **sin datos reales** (IP, MAC, nombres).

Responderé en cuanto pueda. Este es un proyecto personal sin equipo dedicado, así que no puedo prometer plazos.

## Qué se considera una vulnerabilidad

- Ejecución de código o de comandos a partir de datos de la red, de un archivo de captura o de una petición al servidor local.
- Acceso al servidor local sin el secreto de la sesión, o desde otra página web.
- Que un dispositivo o una captura pueda tumbar la aplicación o agotar su memoria sin límite.
- Fuga de datos de la red hacia fuera del equipo.

## Qué no lo es

- Que un dispositivo infectado que se vigila **no sea detectado**: es una limitación de la detección, no de la seguridad de la app (ver los límites en el README).
- Problemas que exigen que el atacante ya tenga control total del equipo.

## Qué se ha revisado

Ver [`docs/SEGURIDAD.md`](docs/SEGURIDAD.md): modelo de amenazas, hallazgos, correcciones y límites conocidos.
