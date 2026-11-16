# Implementación de PPPoE desde cero en Python

Cliente y servidor PPPoE escritos sobre sockets crudos, construyendo cada
trama byte por byte: encabezado Ethernet, encabezado PPPoE, campo de
protocolo PPP y carga útil. Sin bibliotecas que armen las tramas por
nosotros.

Proyecto de la asignatura Tecnologías e Interconexión de Redes I, Facultad
de Ingeniería, UNAM, 2025.

## Qué hace

Implementa la fase de sesión del protocolo PPPoE completa, con las cinco
etapas de una conexión real:

| Etapa | Mensajes | Protocolo |
|---|---|---|
| Negociación de enlace | LCP Configure-Request / Configure-Ack | `0xc021` |
| Autenticación | PAP Authenticate-Request / Ack / Nak | `0xc023` |
| Configuración de red | IPCP Configure-Request / Configure-Ack | `0x8021` |
| Transferencia de datos | Paquetes IP encapsulados | `0x0021` |
| Cierre de sesión | LCP Terminate-Request / Terminate-Ack | `0xc021` |

El servidor valida credenciales y responde con Authenticate-Ack o
Authenticate-Nak según corresponda, cerrando la sesión si fallan.

## Cómo está construido

**Sockets crudos.** Se usa `socket.AF_PACKET` con `SOCK_RAW` para operar
directamente en la capa de enlace. Esto da control total sobre cada byte
transmitido, a cambio de tener que construirlo todo a mano.

**Encapsulamiento manual.** Cada trama se arma con `struct.pack`,
respetando el formato del RFC 2516: versión y tipo en un byte, código,
identificador de sesión y longitud. El EtherType `0x8864` marca la trama
como PPPoE en fase de sesión.

**Máquina de estados por etapas.** Cada paso del protocolo es una función
independiente que escucha el mensaje esperado, lo valida, construye la
respuesta y encadena el siguiente paso. El flujo avanza por eventos, no
por un ciclo secuencial.

**Captura filtrada.** Se escucha solo tráfico PPPoE con el filtro
`ether proto 0x8864`, para no procesar paquetes ajenos a la sesión.

## Validación

El flujo se verificó capturando las tramas con Wireshark y comparando los
campos de cada encabezado contra la especificación, confirmando que los
mensajes aparecen reconocidos por su nombre de protocolo y en el orden
correcto.

## Referencias

- RFC 2516, método para transmitir PPP sobre Ethernet
- RFC 1661, Point-to-Point Protocol
- RFC 1332, PPP Internet Protocol Control Protocol
- RFC 1334, PPP Authentication Protocols

## Cómo ejecutarlo

Requiere Linux, Python 3, Scapy y privilegios de root, ya que los sockets
crudos no están disponibles para usuarios sin privilegios. Necesita dos
equipos conectados por Ethernet, o dos interfaces físicas distintas.

```bash
pip install scapy

# En el equipo servidor
sudo python3 servidor.py

# En el equipo cliente
sudo python3 cliente.py
```

Antes de ejecutar, ajusta la constante `IFACE` en ambos archivos al nombre
de tu interfaz de red, que puedes consultar con `ip link`.

## Alcance y limitaciones

Son decisiones conscientes del proyecto, no omisiones:

- Implementa la **fase de sesión**, no la de descubrimiento. No hay
  PADI, PADO, PADR ni PADS; el identificador de sesión está fijo en
  `0x0001`.
- La autenticación es **PAP**, que transmite las credenciales en texto
  plano. Es insegura por diseño del protocolo y se eligió por claridad
  didáctica. En producción se usaría CHAP.
- Las credenciales del servidor están escritas en el código, por tratarse
  de un entorno de laboratorio.
- IPCP negocia las opciones pero no asigna direcciones dinámicamente.

## Autores

Proyecto desarrollado en equipo por Andru Isai Delgadillo Nieto, Eduardo
García Reynoza y Gustavo Serrano Madrid.
