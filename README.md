# Adereso para clientes en Codex

Plugin público de Codex para trabajar con los datos y bots que una organización tiene autorizados en Adereso Desk y Adereso Studio.

Este repositorio contiene solamente la configuración pública del plugin, su skill y documentación. No contiene Adereso Memory, código de los servicios Adereso, credenciales, datos de clientes ni configuración de infraestructura interna.

## Qué permite hacer

Según los permisos asociados a la API key de Desk, Codex puede:

- consultar los permisos y recursos autorizados;
- leer tickets, mensajes y eventos de Desk;
- buscar tickets por el identificador de país del contacto;
- listar y consultar bots de Studio;
- editar borradores de bots;
- crear, activar y ejecutar pruebas de QA;
- crear una versión numerada a partir de un borrador revisado, sin publicarla;
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

> Usa `$adereso-client` para mostrar mis permisos y listar los bots de Studio a los que tengo acceso.

Codex consulta `adereso_get_permissions` para conocer las capacidades de la conexión. Después usa `studio_list_organizations` o `desk_list_establishments` para obtener los recursos autorizados. Las herramientas de Studio reciben el `organization_id` devuelto por su directorio; las de Desk, el `establishment_id` del suyo. No hay que inventar esos IDs a partir de nombres de bots, clientes o tickets.

Ejemplos:

- “Busca los tickets recientes de este contacto y resume el problema.”
- “Lista los bots disponibles y explícame qué hace el bot de soporte.”
- “Propón cómo actualizar el borrador de este bot, pero no hagas cambios todavía.”
- “Agrega este caso a QA, revisa si se puede ejecutar y prueba el borrador sin efectos externos.”
- “Crea una versión numerada del borrador revisado, pero no la publiques.”

## Editar y probar un bot

1. Pide a Codex que liste los bots autorizados y lea la configuración del borrador. Revisa con él el cambio propuesto antes de guardarlo.
2. Si autorizas la edición, Codex aplica los cambios al **borrador**. Esto no cambia el bot que atiende conversaciones en vivo.
3. Revisa los casos de QA, ejecuta las pruebas pertinentes sobre el borrador y examina el resultado. Las pruebas bloquean los efectos externos; un resultado con integraciones simuladas no confirma que funcionen en producción.
4. Cuando el borrador esté revisado, puedes pedir una versión numerada. Se crea sin tráfico. **Publicarla es una acción posterior y separada** que debes autorizar expresamente.

Cada paso depende de los permisos concedidos por el administrador. Pide a Codex que te muestre el resultado de cada cambio y prueba antes de continuar.

## Alcance de los permisos

La API key determina dos ámbitos independientes:

| Producto | Alcance |
| --- | --- |
| Desk | El establishment al que pertenece la API key y sus scopes autorizados. |
| Studio | La organización Studio verificada para ese establishment y las capacidades asignadas por el administrador. |

Una key puede tener lectura en Desk sin acceso a Studio, o lectura en ambos productos sin permiso para editar bots. El servicio vuelve a evaluar la autorización; rotar o revocar la key, deshabilitar MCP o cambiar sus capacidades afecta las conexiones asociadas.

El servidor comprueba que el `establishment_id` u `organization_id` enviado corresponda al alcance validado de la key. Enviar otro ID no concede acceso a recursos ajenos.

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
codex plugin marketplace upgrade adereso-clients
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

El catálogo actual permite lectura de Desk y lectura, edición de borradores, QA, creación de versiones numeradas sin tráfico y publicación separada de versiones existentes en Studio, siempre según permisos. La creación de bots todavía no forma parte del catálogo público.
