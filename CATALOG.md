# Catálogo

Este marketplace contiene un único plugin público:

| Plugin | Propósito | Autenticación |
| --- | --- | --- |
| `adereso-client` | Trabajar con tickets de Desk y bots de Studio dentro del alcance autorizado del cliente. | OAuth 2.0 con PKCE y una API key de Desk habilitada para MCP. |

El manifiesto del marketplace está en [`.agents/plugins/marketplace.json`](.agents/plugins/marketplace.json) y el plugin en [`plugins/adereso-client`](plugins/adereso-client).

La lista efectiva de tools depende de los permisos de cada conexión. `adereso_get_permissions` muestra las capacidades; `studio_list_organizations` y `desk_list_establishments` entregan, respectivamente, el `organization_id` y el `establishment_id` que requieren las herramientas de cada producto.
