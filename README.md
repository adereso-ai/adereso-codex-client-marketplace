# Adereso para clientes en Codex

Plugin público de Codex para trabajar con los datos y bots que una organización tiene autorizados en Adereso Desk y Adereso Studio.

Este repositorio contiene solamente la configuración pública del plugin, su skill y documentación. No contiene Adereso Memory, código de los servicios Adereso, credenciales, datos de clientes ni configuración de infraestructura interna.

## Qué permite hacer

Según los permisos asociados a la API key de Desk, Codex puede:

- listar el workspace autorizado y sus capacidades;
- leer tickets, mensajes y eventos de Desk;
- buscar tickets por el identificador de país del contacto;
- listar y consultar bots de Studio;
- editar borradores de bots;
- crear, activar y ejecutar pruebas de QA;
- publicar una versión numerada existente.

Las herramientas disponibles se calculan para cada conexión. Una cuenta con permisos de lectura no recibe herramientas de escritura.

## Requisitos

- Codex con soporte para plugins y MCP remoto;
- una API key **no-core** de Desk;
- acceso MCP habilitado para esa key por un administrador del establishment;
- permisos Studio configurados si se necesita consultar o modificar bots.

Las API keys existentes no quedan habilitadas automáticamente. Solicita al administrador de tu cuenta Adereso que habilite MCP y asigne las capacidades necesarias.

## Instalación

Ejecuta:

```bash
codex plugin marketplace add adereso-ai/adereso-codex-client-marketplace
codex plugin add adereso-client@adereso-clients
codex mcp login adereso
```

El último comando abre en el navegador el acceso seguro de Adereso. Ingresa allí la API key de Desk. Nunca pegues la key en una conversación, prompt, repositorio, comando ni llamada de herramienta.

Abre una conversación nueva después de instalar o actualizar el plugin, para que Codex cargue sus tools e instrucciones.

## Primer uso

Puedes comenzar con:

> Usa `$adereso-client` para listar mis workspaces autorizados y los bots de Studio disponibles.

Codex llamará primero a `adereso_list_workspaces`. Esa herramienta devuelve el `workspace_ref` opaco y las capacidades efectivas de la conexión. Las demás herramientas exigen ese valor; no se debe inferir desde nombres de clientes, bots o tickets.

Ejemplos:

- “Busca los tickets recientes de este contacto y resume el problema.”
- “Lista los bots disponibles y explícame qué hace el bot de soporte.”
- “Agrega este caso al suite de QA y ejecuta las pruebas.”
- “Actualiza el borrador del bot con este comportamiento.”

Codex solicita confirmación antes de las herramientas que escriben o publican cambios.

## Alcance de los permisos

La API key determina dos ámbitos independientes:

| Producto | Alcance |
| --- | --- |
| Desk | El establishment al que pertenece la API key y sus scopes autorizados. |
| Studio | La organización Studio verificada para ese establishment y las capacidades asignadas por el administrador. |

Una key puede tener lectura en Desk sin acceso a Studio, o lectura en ambos productos sin permiso para editar bots. El servicio vuelve a evaluar la autorización; rotar o revocar la key, deshabilitar MCP o cambiar sus capacidades afecta las conexiones asociadas.

El plugin no ofrece acceso a otros establishments ni organizaciones mediante IDs enviados por el cliente. El servidor vincula cada `workspace_ref` con el alcance validado de la key.

## Cómo funciona la autenticación

1. Codex inicia OAuth 2.0 con PKCE contra `https://mcp.adereso.ai`.
2. La página de Adereso solicita la API key de Desk una vez.
3. Adereso valida que la key esté activa y habilitada para MCP.
4. El MCP emite credenciales propias para la sesión de Codex.

El MCP no persiste la API key original. La key continúa funcionando en Desk y puede rotarse o revocarse desde sus mecanismos habituales. Si cambia, ejecuta nuevamente:

```bash
codex mcp login adereso
```

## Actualización

Vuelve a instalar el plugin desde el marketplace y abre una conversación nueva:

```bash
codex plugin add adereso-client@adereso-clients
```

Si una versión anterior apuntaba a un endpoint `run.app`, actualiza el plugin y repite `codex mcp login adereso`. El endpoint público vigente es `https://mcp.adereso.ai/mcp`.

## Solución de problemas

**No aparecen tools de Adereso.** Confirma que el plugin esté instalado, abre una conversación nueva y ejecuta `codex mcp login adereso`.

**La API key es rechazada.** La key debe estar activa, ser no-core y tener MCP habilitado. Un administrador de Adereso Desk debe revisar su configuración.

**Puedo leer Desk, pero no veo Studio.** El establishment debe tener una organización Studio verificada y la key debe contar con capacidades Studio.

**Falta una tool de escritura.** La conexión no tiene esa capacidad. Solicita al administrador que ajuste los permisos y vuelve a iniciar sesión.

**La sesión dejó de funcionar.** La key pudo ser rotada, revocada o deshabilitada. Conecta nuevamente con la key vigente.

## Seguridad y privacidad

Los tickets, conversaciones, trazas y configuraciones de bots pueden contener datos personales o confidenciales. Usa el plugin de acuerdo con las políticas de tu organización y concede únicamente los permisos necesarios.

No publiques credenciales en issues. Para reportar una vulnerabilidad, usa las instrucciones de [SECURITY.md](SECURITY.md).

Este repositorio se audita en cada cambio para impedir credenciales y archivos de secretos. Consulta [CONTRIBUTING.md](CONTRIBUTING.md) para validar cambios locales.

## Estado del catálogo

El catálogo actual permite lectura de Desk y lectura, edición de borradores, QA y publicación de versiones numeradas existentes en Studio, siempre según permisos. La creación de bots y de versiones numeradas todavía no forma parte del catálogo público.

