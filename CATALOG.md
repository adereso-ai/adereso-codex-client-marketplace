# Catálogo

Este marketplace contiene un único plugin público:

| Plugin | Propósito | Autenticación |
| --- | --- | --- |
| `adereso-client` | Trabajar con tickets de Desk y bots de Studio dentro del alcance autorizado del cliente. | OAuth 2.0 con PKCE y una API key de Desk habilitada para MCP. |

El manifiesto del marketplace está en [`.agents/plugins/marketplace.json`](.agents/plugins/marketplace.json) y el plugin en [`plugins/adereso-client`](plugins/adereso-client).

La lista efectiva de tools depende de los permisos de cada conexión. `adereso_list_workspaces` es el punto de entrada y entrega el `workspace_ref` requerido por las tools de producto.

