# Preserved component notes

Editorial copy of the previous README. Workstation paths are normalized; original source and immutable evidence are not modified. Earlier status claims belong to their named checkpoints, not the live device. Start with the current [README](../README.md).

# Original Firmware Reverse Engineer

Ingeniería inversa legible del paquete OEM `provider-webformat.bin` del HGW-500BNA-QCv2 A2. El análisis del 3 de noviembre de 2026 conserva la estructura RAS, la configuración del kernel recuperada, veinte scripts de arranque exactos y las fuentes GPL de referencia de plataforma, reset y SPI.

La imagen analizada tiene 6.729.728 bytes y SHA-256 `f39ed40cc66010287574bdc41c9fc18a6ba7d674f7c0acd7d7d47f8ab633a42f`. Su cuerpo local está en `../HGW500/firmware/oem/provider-webformat.bin`.

La investigación del 7 de noviembre conserva el análisis DDR OEM (`docs/DDR_OEM_ANALYSIS_20261107.md`; maintainer-workspace reference) y los contratos Topaz reconstruidos (`docs/TOPAZ_CONTRACTS_20261107.md`; maintainer-workspace reference): segundo SDK fijado, precondiciones MMIO, comparación de las111 escrituras y carga SRAM. El ensayo físico reset-only separa pérdida de MDLR/programación y confirma retorno OEM por watchdog; otro test comprueba patrones independientes en una pareja de direcciones separadas64MiB, con restauración. La revisión de reloj/modos y CPU–DMA distingue hipótesis, código y prueba física; la entrada propia desde encendido y los128MiB completos siguen sin aceptación.

| Región de la imagen | Inicio | Fin exclusivo | Contenido comprobado |
| --- | --- | --- | --- |
| Cabecera RAS | 0 | 8.192 | uImage de 64 bytes y área reservada |
| Kernel comprimido | 8.192 | 1.188.509 | LZMA, kernel expandido de 3.750.104 bytes |
| Alineación | 1.188.509 | 1.245.184 | 56.675 bytes |
| Sistema de archivos | 1.245.184 | 6.729.728 | SquashFS 4.0 little-endian, LZMA |

Los CRC de cabecera y payload son correctos. El payload declarado por RAS incluye el kernel comprimido, la alineación y el SquashFS. La primera secuencia LZMA termina antes del sistema de archivos. El SquashFS declara 5.481.061 bytes útiles, 1.114 inodos y bloques de 524.288 bytes.

`source/oem-kernel.config.sanitized` procede del IKCONFIG GZIP recuperado por REA dentro del kernel. Declara Linux 2.6.35.12. `source/oem-rootfs-scripts/` contiene los veinte scripts y declaraciones de arranque exportados sin cambiar sus bytes. El filtro omite un archivo que contiene referencias a credenciales. `analysis/source-manifest.json` registra el origen, tamaño y hash de los 42 archivos conservados.

`source/reference-gpl/` conserva código de Quantenna-GPL fijado en `116a8b0cd80d75e6bc3b8d21646f9c7fa4ce1cf9`. Esa referencia pertenece a la línea v37.4.0.62.1. La línea binaria OEM documentada es v37.4.0.89 y su fuente completa sigue pendiente de vincular con la imagen. Los avisos de copyright se conservan en los archivos y el texto GPL está en `COPYING.GPL-2.0`.

REA 6.8.0 ejecutó inspección de formato, entropía y extracción con Unblob 26.6.4. `analysis/rea-summary.json`, `rea-entropy.json` y `rea-extraction.json` conservan los resultados y hashes de las evidencias. La extracción tiene cobertura parcial. REA rechaza el contenedor RAS como formato binario para análisis nativo. `unsquashfs` 4.6.1 sí permitió listar el SquashFS LZMA y recuperar la selección de scripts. El kernel y los ejecutables OEM conservan trabajo de desensamblado y reconstrucción pendiente.

Para comprobar la entrega se ejecuta `python tools/verify_repository.py`.

La estructura de otra imagen se comprueba con un destino JSON nuevo.

```powershell
python tools/inspect_ras.py ../HGW500/firmware/oem/provider-webformat.bin out/ras-new.json
```

La extracción reproducible de scripts usa Linux y un directorio privado en ext4.

```powershell
wsl -d Engineering -u apelsito --exec python3 ${WORKSPACE}/hgw500-original-firmware-reverse-engineer/tools/extract_oem_scripts.py ${WORKSPACE}/HGW500/firmware/oem/provider-webformat.bin ${EVIDENCE_ROOT}/out/oem-scripts-new ${WORKSPACE}/hgw500-original-firmware-reverse-engineer/out/scripts-new
```

REA se repite con `tools/run_rea.py IMAGEN DIRECTORIO_PRIVADO_EN_OUT JSON_RESUMEN`, seguido de `tools/export_rea_metadata.py DIRECTORIO_PRIVADO DIRECTORIO_ANALISIS`. Los directorios y archivos de salida deben ser nuevos. Los cuerpos, las evidencias completas y los intermedios permanecen en `out/` local o en el `out/` privado de ext4. El repositorio remoto debe conservar visibilidad privada.

## Arquitectura de procesamiento del HGW500

El [esquema y sus evidencias](../docs/HARDWARE_ARCHITECTURE.md), conservados el
3 de noviembre de 2026, identifican una CPU LHost ARC750 a 500 MHz y cuatro
coprocesadores: MuC, AuC, DSP y la MCU 8051 del RTL8192EE. Incluyen el inventario
SPI NOR de 16 MiB y el perfil DDR3 OEM de 128 MiB, con fuentes y límites.

![Arquitectura de procesamiento del HGW500](../docs/hardware/hgw500-processing-architecture.png)

El diagrama es una vista conceptual. La etiqueta qdrv describe el papel del
host; la integración física de 5 GHz en Core Boot R1 sigue pendiente.
