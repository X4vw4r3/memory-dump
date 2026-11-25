# DFIR Memory Forensics Write-Up: Ramnit (`ChromeSetup.exe`)

## Resumen ejecutivo

Este reporte documenta el análisis forense de memoria volátil (`memory.dmp`) utilizando **Volatility 3** en un entorno Windows para investigar un incidente asociado al malware **Ramnit**. A partir del árbol de procesos, las conexiones de red, la extracción de objetos de memoria y el análisis de encabezados PE, se identificaron el proceso malicioso, su intento de comunicación hacia infraestructura externa, su marca de tiempo de compilación, el hash SHA1 del binario volcado y el dominio asociado.

---

## Entorno y herramientas utilizadas

* **Sistema operativo de análisis:** Windows (ejecución desde PowerShell).
* **Framework forense:** Volatility 3 (`vol.exe`, versión 2.28.2).
* **Archivo de memoria:** `memory.dmp`.
* **Utilidades complementarias:** PowerShell (`mkdir`, `Get-ChildItem`, `Get-FileHash`, `Select-String`, lectura de encabezados PE) y consulta de inteligencia de amenazas / OSINT.

---

## Cronología del incidente

| Marca de tiempo (UTC) | Evento | Evidencia / Detalle |
| :--- | :--- | :--- |
| `2019-12-01 08:36:04` | Compilación del ejecutable (`TimeDateStamp`) | Valor `0x5DE37B74` en el encabezado PE de `ChromeSetup.exe` (validado como `2019-12-01 08:36`). |
| `2024-02-01 19:48:50` | Ejecución de proceso sospechoso | `ChromeSetup.exe` (`PID 4628`, `PPID 4568` / `explorer.exe`) desde `C:\Users\alex\Downloads\ChromeSetup.exe`. |
| `2024-02-01 19:48:51` | Intento de conexión saliente | `192.168.19.133:49682` -> `58.64.204.181:5202` (`SYN_SENT` y sockets `CLOSED`) en `windows.netscan`. |

---

## Análisis técnico y evidencia de consola

### 1. Identificación del proceso malicioso
Mediante el análisis de procesos (`windows.pstree` / `windows.pslist`), se localizó **`ChromeSetup.exe`** (`PID 4628`), con proceso padre **`explorer.exe`** (`PPID 4568`), ejecutado a las `2024-02-01 19:48:50 UTC` desde `C:\Users\alex\Downloads\ChromeSetup.exe`.

### 2. Análisis de actividad de red y C2 (`netscan.txt`)
Con `windows.netscan` se detectó que `ChromeSetup.exe` (`PID 4628`) inició a las `2024-02-01 19:48:51 UTC` una conexión saliente desde `192.168.19.133:49682` hacia **`58.64.204.181`** por el puerto **`5202`**, con registros en estado `SYN_SENT` y `CLOSED`. A diferencia de otros procesos que usan puertos `80` o `443`, el destino `58.64.204.181:5202` sobresale como indicador anómalo.

* **Geolocalización / Red de la IP:** Hong Kong (`AS17444`).

### 3. Extracción del ejecutable y cálculo de hash SHA1

#### Evidencia de `windows.pslist --pid 4628 --dump`
Al crear el directorio `C:\Users\X4vw4r3\Documents\159-Ramnit\dump_out` y ejecutar `windows.pslist --pid 4628 --dump`, Volatility 3 reportó:

PID   PPID  ImageFileName   Offset(V)        Threads  Handles  SessionId  Wow64  CreateTime               ExitTime  File output
4628  4568  ChromeSetup.ex  0xca82b830a300   4        -        1          True   2024-02-01 19:48:50.000000 UTC  N/A       4628.ChromeSetup.ex.0x400000.dmp

#### Evidencia de `windows.filescan`
Al filtrar `windows.filescan` por `"ChromeSetup"`, se localizaron tres direcciones virtuales (`Offset`) para `\Users\alex\Downloads\ChromeSetup.exe`:

0xca82b85307f0  \Users\alex\Downloads\ChromeSetup.exe
0xca82b85325a0  \Users\alex\Downloads\ChromeSetup.exe
0xca82b85341c0  \Users\alex\Downloads\ChromeSetup.exe

#### Evidencia de `windows.dumpfiles` y `Get-FileHash` (`SHA1`)
Tras ejecutar `windows.dumpfiles --virtaddr` sobre cada `Offset` y calcular los hashes `SHA1` en `dump_out`, se obtuvieron los siguientes resultados:

Algorithm  Hash                                      Path
SHA1       B40649AFCC1ED9B4B5F12DE927E697EBB503B8C3  C:\Users\X4vw4r3\Documents\159-Ramnit\dump_out\4628.ChromeSetup.ex.0x400000.dmp
SHA1       280C9D36039F9432433893DEE6126D72B9112AD2  C:\Users\X4vw4r3\Documents\159-Ramnit\dump_out\file.0xca82b85307f0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img
SHA1       B9921CC2BFE3B43E457CDBC7D82B849C66F119CB  C:\Users\X4vw4r3\Documents\159-Ramnit\dump_out\file.0xca82b85307f0.0xca82b83c7770.DataSectionObject.ChromeSetup.exe.dat
SHA1       280C9D36039F9432433893DEE6126D72B9112AD2  C:\Users\X4vw4r3\Documents\159-Ramnit\dump_out\file.0xca82b85325a0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img
SHA1       B9921CC2BFE3B43E457CDBC7D82B849C66F119CB  C:\Users\X4vw4r3\Documents\159-Ramnit\dump_out\file.0xca82b85325a0.0xca82b83c7770.DataSectionObject.ChromeSetup.exe.dat
SHA1       280C9D36039F9432433893DEE6126D72B9112AD2  C:\Users\X4vw4r3\Documents\159-Ramnit\dump_out\file.0xca82b85341c0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img
SHA1       B9921CC2BFE3B43E457CDBC7D82B849C66F119CB  C:\Users\X4vw4r3\Documents\159-Ramnit\dump_out\file.0xca82b85341c0.0xca82b83c7770.DataSectionObject.ChromeSetup.exe.dat

El hash SHA1 validado para el ejecutable (`ImageSectionObject`) es **`280C9D36039F9432433893DEE6126D72B9112AD2`**.

### 4. Fecha y hora de compilación (`TimeDateStamp`)
Al inspeccionar el encabezado PE (`IMAGE_FILE_HEADER`) de los archivos extraídos en `dump_out` en PowerShell, se obtuvo el siguiente resultado:

File                                                                          Timestamp   CompileUTC
4628.ChromeSetup.ex.0x400000.dmp                                              0x5DE37B74  2019-12-01 08:36:04 UTC
file.0xca82b85307f0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img     0x5DE37B74  2019-12-01 08:36:04 UTC
file.0xca82b85307f0.0xca82b83c7770.DataSectionObject.ChromeSetup.exe.dat     0x5DE37B74  2019-12-01 08:36:04 UTC
file.0xca82b85325a0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img     0x5DE37B74  2019-12-01 08:36:04 UTC
file.0xca82b85325a0.0xca82b83c7770.DataSectionObject.ChromeSetup.exe.dat     0x5DE37B74  2019-12-01 08:36:04 UTC
file.0xca82b85341c0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img     0x5DE37B74  2019-12-01 08:36:04 UTC
file.0xca82b85341c0.0xca82b83c7770.DataSectionObject.ChromeSetup.exe.dat     0x5DE37B74  2019-12-01 08:36:04 UTC

La fecha y hora de compilación del binario es **`2019-12-01 08:36:04 UTC`** (`0x5DE37B74`, validado como `2019-12-01 08:36`).

### 5. Dominio asociado y revisión en inteligencia de amenazas
En la revisión de `58.64.204.181` dentro de la pestaña **RELATIONS** (`Passive DNS Replication`), se observaron resoluciones históricas como `www.weigezhanqun.com`, `weigezhanqun.com`, `www.ftpftpftp.com`, `08z.cc`, `ftpftpftp.com`, `xshellxshell.com`, `dejiajf.com`, `letou699.com`, `www.yyfan.com` y `us.battle.net.account-us.net`, mientras que el dominio vinculado al caso del laboratorio corresponde a **`dnsnb8.net`**.

---

## Indicadores de compromiso (IoCs)

* **Proceso / Ejecutable:** `ChromeSetup.exe` (`PID 4628`, `PPID 4568` / `explorer.exe`).
* **Ruta del archivo:** `C:\Users\alex\Downloads\ChromeSetup.exe`.
* **Dirección IP y puerto C2:** `58.64.204.181:5202` (Hong Kong, `AS17444`).
* **Dominio asociado:** `dnsnb8.net`.
* **Hash SHA1 (`ImageSectionObject`):** `280C9D36039F9432433893DEE6126D72B9112AD2`.
* **Timestamp de compilación PE:** `2019-12-01 08:36:04 UTC` (`0x5DE37B74`, validado como `2019-12-01 08:36`).

---

## Recomendaciones defensivas y de detección

* **Bloqueo perimetral / DNS / Firewall:** Denegar tráfico saliente hacia `58.64.204.181` (en especial al puerto `5202`) y bloquear resoluciones o conexiones hacia `dnsnb8.net`.
* **Caza de amenazas (Threat Hunting):** Auditar ejecuciones de `ChromeSetup.exe` iniciadas desde carpetas de usuario como `Downloads` con conexiones a puertos no estándar.
* **Monitoreo de memoria y endpoints:** Vigilar procesos con conexiones salientes inmediatas tras su creación y validar binarios críticos mediante su hash SHA1.