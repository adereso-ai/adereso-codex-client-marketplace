# Contribuir

## Principios

- Mantén el repositorio apto para publicación: no agregues secretos, datos de clientes ni detalles internos de infraestructura.
- Nunca uses una API key real en documentación, fixtures, logs o ejemplos.
- Mantén los permisos mínimos y solicita confirmación para tools que escriben o publican.
- Incrementa la versión del plugin cuando una actualización deba llegar a quienes ya lo instalaron.

## Validación local

Desde la raíz del repositorio, ejecuta:

```bash
python3 -m pip install --requirement requirements-audit.txt
python3 scripts/audit_public_repo.py --history
python3 -m unittest discover -s tests
python3 /ruta/a/plugin-creator/scripts/validate_plugin.py plugins/adereso-client
```

El primer comando instala el parser YAML fijado para el auditor. El segundo inspecciona todos los blobs alcanzables del historial y no imprime el contenido detectado. El tercero prueba las reglas del escáner. El cuarto valida la estructura del plugin con la skill `plugin-creator` incluida en Codex.

Revisa también que `.agents/plugins/marketplace.json` siga apuntando a `./plugins/adereso-client` y que el endpoint MCP sea `https://mcp.adereso.ai/mcp`.

## Cambios de comportamiento

Actualiza README, la skill y el catálogo cuando cambien las tools, el flujo de autenticación o el modelo de permisos. Describe en el pull request cómo validaste la instalación y el inicio de sesión, sin adjuntar tokens ni respuestas con datos reales.
