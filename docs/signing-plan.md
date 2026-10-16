# PLAN: Signing-Service v1 — Cierre de diseño y pendientes

**Contexto para quien continúe este trabajo (Claude Code local):** este plan parte de una
primera versión funcional de `signing-service` (firma de documento único vía HSM, PIN de
firma y sesión de firma ya implementados). Los puntos abajo son decisiones de diseño ya
tomadas y acordadas — no hay que re-discutirlas, solo implementarlas. Referencian ADRs ya
existentes en `platform-docs` (ADR-002, ADR-003, ADR-004, ADR-005) y la migración 016 de
`migrations` (`tsa_token`, `tsa_provider`, `tsa_sealed_at` en `signatures`).

---

## 0. Qué ya existe y no se toca
- Firma vía `hsm-service` (recibe hash, PIN, slot/certificado) — funciona.
- PIN de firma + sesión de firma (`session_token`/`session_expires_at`) — ya implementado
  según ADR-005, mantener como está.
- Validación de JWT + auditoría hybrid (fallback a escritura directa en `audit_logs`) — ya
  portado desde `certificate-service`, mantener el mismo patrón.
- Llamada a `certificate-service` para validar certificado/cadena antes de firmar — ya
  existe, no modificar.

## 1. Corregir quién hashea y qué se firma realmente

**Problema actual:** el endpoint recibe `document_b64` (correcto, nunca aceptar un hash
calculado por el cliente — riesgo de oráculo de firma), pero la respuesta trae
`"signature_format": "RAW"` — eso significa que hoy se firma un hash plano, no se produce
una estructura PAdES real embebida en el PDF.

**Tareas:**
- [x] Reemplazar la generación de firma "RAW" por una implementación PAdES real. Usar una
  librería que entienda incremental updates de PDF y byte-range signing (ej. `pyHanko` en
  Python — ya soporta PAdES-B y PAdES-LTV). No construir el cálculo de byte-range a mano.
- [x] El hash que se firma debe calcularse **sobre el byte-range específico del PDF**
  (todo el archivo excepto el placeholder reservado para la firma), nunca
  `SHA256(archivo completo)` directo — esto lo calcula la librería de PAdES, no código propio.
- [x] `signature_format` en la respuesta debe reflejar el formato real producido (`PAdES-B`
  o el perfil que se use), no quedar como `RAW`.
- [x] Confirmar alcance de formatos para v1: solo PAdES/PDF (DLT-011 contempla también
  XAdES/CAdES, pero quedan fuera de esta versión — no implementarlos ahora).

## 2. `document_name` — tratarlo solo como metadata, nunca como insumo de lógica
- [x] No usarlo para construir rutas de archivo en disco (riesgo de path traversal). Nunca
  se usó así — es un `str` que viaja de `SignDocumentCommand` a `SignatureRecord.document_name`
  sin tocar el filesystem en ningún punto.
- [x] No usarlo para decidir el tipo de procesamiento — detectar el tipo real inspeccionando
  los primeros bytes del archivo recibido (magic bytes: un PDF inicia con `%PDF-`). Rechazar
  con error claro si el contenido no corresponde a un PDF válido, independientemente de lo
  que diga `document_name`. Ya implementado como parte del punto 1 (`SignDocumentUseCaseImpl.
  execute()`, chequeo `%PDF-` antes de cualquier otra cosa) — `PyHankoPAdESSigner.sign_pdf()`
  tiene el mismo chequeo como segunda capa.
- [x] Guardarlo únicamente como columna de texto en `signing_requests`, para
  display/auditoría humana. Confirmado: único uso es `signing_requests.document_name`.

Las tres cajas ya estaban satisfechas por la implementación del punto 1 — no hizo falta
código nuevo, solo verificación. Tests de regresión agregados para que esto no se rompa sin
aviso: `test_document_name_cannot_override_the_real_content_check` (un `document_name` que
miente sobre el contenido no cambia el resultado) y `test_document_name_is_stored_verbatim_as_inert_text`
(un `document_name` con forma de path traversal se persiste como texto plano, sin efecto alguno).

## 3. Integración real con el TSA (ADR-002) — pendiente, no cosmético
- [ ] Implementar cliente HTTP hacia el TSA primario (ANF AC free tier), con fallback a
  Certum/FreeTSA.org, y pseudo-timestamp local (hash + hora de pared, logueado) si ambos
  fallan, con re-sellado posterior cuando un TSA real esté disponible — tal como describe
  ADR-002.
- [ ] Lo que se sella con el TSA es **el valor de la firma**, no el documento original ni su
  hash directo — sellar después de firmar, nunca antes.
- [ ] Embeber el token TSA (RFC 3161, DER) como atributo no firmado dentro de la estructura
  CMS/PAdES (la librería de PAdES del punto 1 debería soportar esto directamente).
- [ ] Persistir `tsa_token`, `tsa_provider`, `tsa_sealed_at` en la fila de `signatures`
  correspondiente (verificar existencia de las columnas).
- [ ] Si el sellado falla (ambos TSA caídos), el flujo no debe bloquear la firma — persistir
  el pseudo-timestamp local y marcar la fila para re-sellado posterior (puede ser un job o un
  endpoint de reintento explícito, no algo automático en cada GET — ver punto 5).

## 4. Soporte para N firmantes — rediseño del flujo de endpoints

**Modelo:** un `signing_request` agrupa el documento y el proceso de firma de varios
firmantes sobre el mismo archivo; cada `sign` agrega una firma incremental sobre el estado
actual del documento.

### 4.1 Esquema de datos (nuevo, para `migrations`)
- [ ] Tabla `signing_requests`: `id` (UUID), `tenant_id`, `document_name`, `signers_number`,
  `signatures_count` (default 0), `status` (`PENDING` | `COMPLETED` | `PENDING_TSA_RETRY`),
  `document_blob` (`LONGBLOB`, el PDF en su estado actual/final), `created_at`,
  `completed_at` (nullable).
- [ ] `signatures` ya existente: agregar FK `signing_request_id` → `signing_requests.id`
  (si no existe ya una relación equivalente).
- [ ] Nueva migración con su `.down.sql` correspondiente, siguiendo el patrón ya establecido
  en el repo `migrations` (triggers/procedures donde aplique, revisar `AGENTS.md` del repo).

### 4.2 Endpoints
- [ ] **`POST /signing-requests`** — crea el `signing_request`. Recibe `document_b64`
  (una sola vez), `document_name`, `signers_number`. Guarda el documento en
  `document_blob`, estado `PENDING`, `signatures_count = 0`. Responde `signing_request_id`.
- [ ] **`POST /signing-requests/{id}/sign`** — reemplaza al endpoint actual de firma única.
  Recibe `certificate_id` + `pin` (+ `session_token` si aplica por ADR-005) — **ya no recibe
  `document_b64`**. Lee `document_blob` actual desde la BD, agrega la firma incremental de
  ese firmante sobre el estado actual (no sobre el original ni sobre una copia nueva),
  actualiza `document_blob`, incrementa `signatures_count`.
  - [ ] Si `signatures_count == signers_number` tras esta firma: dispara en el mismo request
    el sellado TSA (punto 3) y marca `status = COMPLETED`, `completed_at = now()`. Esto es la
    finalización real del proceso — nunca disparada por un GET.
  - [ ] Debe seguir idempotente vía `Idempotency-Key` (ADR-004) — reintentar esta llamada no
    debe producir una firma duplicada del mismo firmante.
- [ ] **`GET /signing-requests/{id}`** — solo lectura, sin efectos secundarios. Devuelve
  `status`, `signatures_count`/`signers_number`, y si `status == COMPLETED`, el documento
  final como `document_b64` directo en la respuesta (no generar URLs firmadas ni
  almacenamiento de objetos — no se necesita esa infraestructura a esta escala). Si no está
  completo, devuelve el estado de avance sin el documento final.

### 4.3 Reemplazo de la ruta actual
- [ ] El endpoint de un solo firmante actual puede quedar como azúcar sintáctico sobre este
  flujo (`signers_number = 1`, crear + firmar en una sola llamada combinada) si se quiere
  mantener compatibilidad simple para el caso de un solo firmante — decisión de conveniencia,
  no bloqueante.

## 5. "Obtener copia de un documento ya firmado"
- [ ] No implementar ningún mecanismo de "reconstrucción desde `signatures`" — la fila de
  `signatures` solo debe usarse para trazabilidad (encontrar a qué `signing_request_id`
  pertenece). La copia se obtiene siempre vía `GET /signing-requests/{id}`, que lee
  `document_blob` tal como está guardado.
- [ ] No construir snapshots por firmante (documento "tal como estaba cuando firmé") salvo
  que surja un requisito real explícito — no especular esto ahora.

## 6. Seguridad — checklist final antes de cerrar v1
- [ ] Confirmar que el servicio nunca acepta un hash pre-calculado por el cliente como
  sustituto de `document_b64`.
- [ ] Confirmar que `document_name` no se usa en ninguna ruta de filesystem ni en lógica de
  bifurcación de formato.
- [ ] Confirmar rate-limiting/lockout en la verificación del PIN de firma (ADR-005) —
  si no está implementado todavía, es bloqueante antes de cerrar v1, no opcional.
- [ ] Confirmar que `signing-service` no guarda el PIN de firma en ninguna forma recuperable
  (solo hash), y que no existe ningún mecanismo de "autocompletar"/regenerar el PIN sin que
  el usuario lo reingrese — ver ADR-005, sección de anti-patrón explícitamente rechazado.

## 7. Documentación y cierre
- [ ] `README.md`/`AGENTS.md` de `signing-service` (si no existen) documentando: el flujo de
  N firmantes, la referencia a ADR-002/003/004/005, y la nota de que el formato soportado en
  v1 es solo PAdES.
- [ ] CI básico (reusar patrón ya establecido en `hsm-service`/`certificate-service`).
- [ ] Una vez cerrado: actualizar `security/known-deviations.md` en `platform-docs` si queda
  algún gap consciente (ej. XAdES/CAdES pendientes, reintentos de TSA manuales en vez de
  automáticos) — no cerrar la deuda en silencio, documentarla igual que las anteriores.