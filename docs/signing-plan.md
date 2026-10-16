# PLAN: Signing-Service v1 — Cierre de diseño y pendientes

**Contexto para quien continúe este trabajo (Claude Code local):** este plan parte de una
primera versión funcional de `signing-service` (firma de documento único vía HSM, PIN de
firma y sesión de firma ya implementados). Los puntos abajo son decisiones de diseño ya
tomadas y acordadas — no hay que re-discutirlas, solo implementarlas. Referencian ADRs ya
existentes en `platform-docs` (ADR-002, ADR-003, ADR-005) y la migración 016 de
`migrations` (`tsa_token`, `tsa_provider`, `tsa_sealed_at` en `signatures`). **Nota (punto 7,
cierre):** no existe un "ADR-004" separado de ADR-005 — el archivo se llama
`ADR-004-application-level-signing-PIN-...md` pero su título interno es `ADR-005`; es una
irregularidad de numeración en `platform-docs`, no un documento faltante. Cualquier
referencia a "ADR-004" en este archivo antes del punto 7 (herencia de una versión anterior
de este plan) se refiere a ese mismo documento.

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
  se usó así — es un `str` que viaja de `SignDocumentCommand`/`CreateSigningRequestCommand`
  a `SigningRequest.document_name` sin tocar el filesystem en ningún punto.
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

**Decisión tomada durante la implementación:** ADR-002 nombra el free tier de ANF AC como
primario, pero no existe un endpoint públicamente documentado para él (su propia política de
TSA sugiere que la URL es específica por contrato/suscripción, no pública). Se usó FreeTSA.org
(`https://freetsa.org/tsr`) como primario y Certum (`http://time.certum.pl`) como secundario —
ambos verificados en vivo, gratuitos, sin cuenta. Swapear ANF AC más adelante es un cambio de
config (`TSA_PRIMARY_URL`), no un rediseño. Ver `platform-docs/security/known-deviations.md`
(KD-011).

- [x] Implementar cliente HTTP hacia el TSA primario, con fallback a un secundario, y
  pseudo-timestamp local (hash + hora de pared, logueado) si ambos fallan, con re-sellado
  posterior cuando un TSA real esté disponible — tal como describe ADR-002.
  `app/infrastructure/crypto/fallback_timestamper.py` (`FallbackChainTimeStamper`), sobre
  `pyhanko.sign.timestamps.HTTPTimeStamper` (RFC 3161 real, no construido a mano).
- [x] Lo que se sella con el TSA es **el valor de la firma**, no el documento original ni su
  hash directo — sellar después de firmar, nunca antes. Inherente a cómo pyHanko invoca el
  timestamper (después de que el signer ya produjo `signatureValue`), no algo que este
  servicio tenga que orquestar manualmente.
- [x] Embeber el token TSA (RFC 3161, DER) como atributo no firmado dentro de la estructura
  CMS/PAdES — pyHanko lo soporta directamente vía `async_sign_pdf(..., timestamper=...)`.
  Verificado con el propio validador de pyHanko (`status.timestamp_validity is not None`
  cuando el TSA responde), no solo "no tiró excepción" — ver
  `test_sign_pdf_embeds_real_tsa_token_when_available`.
- [x] Persistir `tsa_token`, `tsa_provider`, `tsa_sealed_at` en la fila de `signatures`
  correspondiente. **Las columnas de la migración 016 no existían en la base de dev
  compartida** pese a que `schema_migrations` reportaba versión 23 limpia — hallazgo real,
  no hipotético (ver `known-deviations.md` KD-012); se aplicó la migración 016 a mano para
  destrabar la verificación. `signature_format` también necesitó una migración nueva (025):
  el ENUM original de la migración 003 (`PKCS7`/`CMS`/`RAW`/`JWS`) no incluía `PAdES-B`/
  `PAdES-T`, así que el `INSERT` real habría fallado bajo `STRICT_TRANS_TABLES` — encontrado
  probando el flujo contra la base real, no asumido.
- [x] Si el sellado falla (ambos TSA caídos), el flujo no debe bloquear la firma — persistir
  el pseudo-timestamp local (`tsa_provider="local-pseudo"`, `tsa_token=NULL`) y marcar la
  fila para re-sellado posterior. `tsa_provider="local-pseudo"` es exactamente esa marca —
  no se construyó el job/endpoint de reintento (explícitamente fuera de alcance, ver texto
  original de este punto y el punto 5).

## 4. Soporte para N firmantes — rediseño del flujo de endpoints ✅ cerrado

**Modelo:** un `signing_request` agrupa el documento y el proceso de firma de varios
firmantes sobre el mismo archivo; cada `sign` agrega una firma incremental sobre el estado
actual del documento.

**Dos hallazgos reales durante la implementación, no anticipados por este plan** (ver
`CLAUDE.md`/`AGENTS.md` para el detalle completo):
- `signatures` tenía una `UNIQUE KEY` real sobre `signing_request_id` (1:1 desde la
  migración 003) — el punto 4.1 de abajo decía "agregar FK si no existe ya una relación
  equivalente" asumiendo que podía no estar; sí estaba, y además como restricción más
  fuerte que una FK (impedía directamente más de una fila por request). Migración 026 la
  relaja a un índice simple.
- `idempotency_keys` es única sobre `(tenant_id, request_id)` solamente, no también
  `operation` — un mismo `request_id` de cliente no puede reclamar dos operaciones
  distintas. Esto bloqueaba la idea obvia de implementar `/sign` componiendo dos llamadas
  separadamente idempotentes ("crear" + "firmar"); se resolvió con un módulo de lógica
  compartida (`signing_core.py`) que no toca idempotencia, y cada endpoint público envuelve
  un único claim alrededor de lo que necesite.

### 4.1 Esquema de datos (nuevo, para `migrations`) ✅
- [x] Tabla `signing_requests` ampliada (ya existía desde la migración 003, no se creó de
  cero): migración 026 agrega `signers_number`, `signatures_count` (default 0), `status`
  (ENUM ampliado con `COMPLETED`/`PENDING_TSA_RETRY`, manteniendo los valores legacy),
  `document_blob` (`LONGBLOB`), `completed_at` (nullable), y `version` (INT, no estaba en
  este plan — necesario para el bloqueo optimista del punto 4.2, ver más abajo).
- [x] `signatures`: la FK a `signing_requests.id` ya existía; lo que hacía falta era relajar
  su `UNIQUE KEY` 1:1 a un índice simple (ver hallazgo arriba) — `026_add_n_signer_support.
  {up,down}.sql`, verificada up→down→up contra la base de dev real.

### 4.2 Endpoints ✅
- [x] **`POST /signing-requests`** — `CreateSigningRequestUseCaseImpl`. Tal como se
  describió: guarda el documento en `document_blob`, estado `PENDING`, `signatures_count=0`.
- [x] **`POST /signing-requests/{id}/sign`** — `SignIncrementUseCaseImpl`. Lee
  `document_blob` actual, agrega la firma incremental de ese firmante (con un `field_name`
  distinto por firmante — pyHanko lo exige), actualiza `document_blob`, incrementa
  `signatures_count`.
  - [x] Si esta firma completa `signers_number`: sella con TSA (punto 3,
    `apply_timestamp=True` solo en esta llamada) y marca `status=COMPLETED`,
    `completed_at=now()`, en el mismo request.
  - [x] Idempotente vía `claim_idempotency_key`/`X-Request-ID`, igual que el resto del
    servicio — `resource_id` es el id de la *firma*, no del `signing_request` (un request
    puede tener más de una firma, a diferencia de antes).
  - [x] **Agregado, no estaba en este plan**: bloqueo optimista (`signing_requests.version`)
    — dos llamadas a este endpoint sobre el mismo id, en simultáneo, no deben poder pisarse
    la una a la otra vía last-write-wins sobre `document_blob`/`signatures_count` (perdería
    silenciosamente la firma de un firmante aunque hsm-service ya la hubiera producido).
    `SigningRequestConflictError` (409) si pierde la carrera — el cliente reintenta, nunca
    reintentado solo del lado del servidor (podría re-disparar PIN/HSM/TSA innecesariamente).
- [x] **`GET /signing-requests/{id}`** — `GetSigningRequestUseCaseImpl`, solo lectura, tal
  como se describió. `document_b64` solo presente si `status == COMPLETED`.

### 4.3 Reemplazo de la ruta actual ✅
- [x] `POST /api/v1/sign` quedó como azúcar sintáctico (`signers_number=1`, crea y firma en
  una sola llamada) — `SignDocumentUseCaseImpl` compone los mismos helpers de
  `signing_core.py` que los dos endpoints nuevos, nunca un camino de código paralelo.
  Contrato de request/response sin cambios para los callers existentes.

**Decisión no anticipada por este plan, tomada durante la implementación:**
`signatures.signature_value` para filas nuevas ya no es el PDF completo (sí lo sigue siendo
para filas viejas, pre-026, de un solo firmante) — es solo el delta incremental que esa
firma agregó (`nuevo_pdf[len(pdf_anterior):]`, exacto porque los incremental updates de PDF
son estrictamente append-only). Esto es justamente lo que pide el punto 5 de abajo ("no
construir snapshots por firmante"): guardar el PDF completo en cada fila de `signatures`
sería exactamente ese snapshot. El único PDF completo vigente vive en
`signing_requests.document_blob`; `/sign` sigue devolviendo el PDF completo en su respuesta,
leído de ahí, no de `signature_value`.

## 5. "Obtener copia de un documento ya firmado" ✅ cerrado (satisfecho por el punto 4)
- [x] No se implementó ningún mecanismo de "reconstrucción desde `signatures`" —
  `GetSigningRequestUseCaseImpl` lee `document_blob` directo, nunca reconstruye nada a
  partir de filas de `signatures`. Esas filas solo sirven para trazabilidad (encontrar a
  qué `signing_request_id` pertenece una firma — `find_signature_by_id`, usado solo para
  replay de idempotencia).
- [x] No se construyeron snapshots por firmante — ver la decisión de `signature_value`
  documentada al cierre del punto 4: cada fila de `signatures` guarda solo su delta
  incremental, nunca un PDF completo "tal como estaba cuando firmé".

## 6. Seguridad — checklist final antes de cerrar v1 ✅ cerrado

Las cuatro cajas eran una auditoría de lo ya construido, no trabajo nuevo — las cuatro
estaban satisfechas, verificadas leyendo el código real (incluido el de `certificate-service`
para la 3ª, que no vive en este repo):

- [x] El servicio nunca acepta un hash pre-calculado — `SignDocumentRequest`,
  `CreateSigningRequestRequest` solo tienen `document_b64` (el documento completo); no existe
  ningún campo de hash en ningún schema de entrada, y `require_pdf()`/`PyHankoPAdESSigner.
  sign_pdf()` chequean los bytes reales (`%PDF-`) antes de cualquier otra cosa.
- [x] `document_name` nunca se usa en rutas de filesystem ni en lógica de bifurcación de
  formato — confirmado en el punto 2 (cerrado), con tests de regresión
  (`test_document_name_cannot_override_the_real_content_check`,
  `test_document_name_is_stored_verbatim_as_inert_text`).
- [x] Rate-limiting/lockout del PIN **sí está implementado** — en `certificate-service`
  (dueño del PIN): `Certificate.apply_failed_pin_attempt()`
  (`app/domain/entities/Certificate.py`) aplica backoff exponencial (dobla desde
  `base_lockout` en cada ciclo de `max_attempts` fallos consecutivos) sin reinicio salvo
  reset explícito, respaldado por `increment_failed_pin_attempts`/`set_pin_lockout` en
  `CertificateRepository` (actualización atómica, no pisa el resto de la fila). El PIN se
  guarda con bcrypt (`bcrypt_pin_hasher.py`). `signing-service` solo traduce los códigos de
  error (`SigningPinInvalidError.remaining_attempts`, `SigningPinLockedError.locked_until`)
  — no implementa su propio rate-limiting porque no es quien posee el estado del PIN.
- [x] `signing-service` nunca guarda el PIN — el parámetro `pin` viaja como argumento de
  función desde `SignIncrementRequest`/`SignDocumentRequest` hasta
  `SigningPinVerifier.verify()` (una llamada HTTP a certificate-service) y nunca se escribe
  en ninguna tabla, log, ni variable de instancia de este servicio. No existe ningún
  endpoint de set/reset de PIN en `signing-service` (esa responsabilidad es enteramente de
  `certificate-service`) — por lo tanto tampoco existe ningún mecanismo de
  "autocompletar"/regenerar.

## 7. Documentación y cierre ✅ cerrado
- [x] `README.md`/`CLAUDE.md`/`AGENTS.md` documentan el flujo de N firmantes (punto 4) y
  ahora también una sección explícita de ADRs (`README.md` → "Decisiones de arquitectura") con
  ADR-002/003/005 y la nota de que v1 solo soporta PAdES (DLT-011 decide también XAdES/CAdES,
  fuera de alcance — ver KD-013 abajo). "ADR-004" no existe como documento separado de
  ADR-005 — ver nota al principio de este archivo.
- [x] CI básico — ya existía (`.github/workflows/ci.yml`), mismo patrón que
  `hsm-service`/`certificate-service` (job `quality` bloqueante, `publish` solo en push a
  `main`). Nada que agregar.
- [x] `platform-docs/security/known-deviations.md` actualizado: **KD-013** — DLT-011 decide
  soporte nativo PAdES+XAdES+CAdES; v1 de este servicio solo implementa PAdES. Decisión de
  alcance consciente (signing-plan.md punto 1), no una laguna silenciosa.