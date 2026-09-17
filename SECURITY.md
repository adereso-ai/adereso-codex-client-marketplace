# Seguridad

## Reportar una vulnerabilidad

No abras un issue público para vulnerabilidades, credenciales expuestas o datos de clientes.

Usa **Security → Report a vulnerability** en este repositorio para enviar el reporte de forma privada. Incluye el impacto, los pasos mínimos para reproducirlo y cualquier mitigación conocida. No incluyas credenciales reales ni datos personales; utiliza valores de prueba o contenido redactado.

## Secretos

Este repositorio es público y no debe contener API keys, tokens, llaves privadas, archivos `.env`, credenciales cloud ni datos de clientes. El script `scripts/audit_public_repo.py` revisa el árbol actual y el historial Git sin imprimir el valor de una coincidencia.

