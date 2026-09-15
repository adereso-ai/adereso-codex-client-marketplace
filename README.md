# Adereso para clientes en Codex

Este marketplace público incluye sólo Adereso MCP. No incluye Adereso Memory ni conocimiento interno.

Un administrador del establishment configura una API key de Desk no-core con `mcp_enabled=true` y capacidades Studio explícitas. Las API keys existentes siguen deshabilitadas por defecto. Los scopes de Desk y los permisos Studio son independientes; el MCP siempre queda acotado al establishment de la key y a la organización Studio verificada.

Para instalar en Codex:

```bash
codex plugin marketplace add adereso-ai/adereso-codex-client-marketplace
codex plugin add adereso-client@adereso-clients
codex mcp login adereso
```

Codex conecta al servicio MCP de clientes, separado del servicio interno, y abre una página OAuth con PKCE para ingresar la API key de Desk una vez. El MCP emite sus propias credenciales de sesión; la API key continúa sirviendo en Desk y no se guarda en el MCP. En la conversación, pide a Codex usar `$adereso-client` y consultar `adereso_list_workspaces` para conocer el `workspace_ref` autorizado.

Una key rotada o revocada exige volver a conectar. El catálogo actual incluye lectura Desk, lectura/edición de borradores Studio, QA y publicación de versiones numeradas existentes según permisos. Crear bots y crear versiones numeradas aún requieren herramientas adicionales.
