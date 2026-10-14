# app/core/logger.py
import logging
import json
from datetime import datetime
from typing import Optional, Dict, Any
import uuid
from app.core.config import get_settings


class UnifiedLogger:
    """
    Logger unificado que:
    - Logs locales estructurados en JSON
    - Preparado para integración futura con audit-service
    - Soporta correlación de requests
    """

    def __init__(self, service_name: str):
        self.service_name = service_name
        self.settings = get_settings()

        # Configurar logger local
        self.logger = logging.getLogger(service_name)
        self._setup_local_logging()

    def _setup_local_logging(self):
        """Configura logging local estructurado en formato JSON"""
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(message)s"  # Solo el mensaje JSON, sin metadatos extra
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def _create_log_entry(
        self,
        level: str,
        message: str,
        action: Optional[str] = None,
        user_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Crea una entrada de log estructurada"""
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "service": self.service_name,
            "level": level,
            "message": message,
            "action": action,
            "user_id": user_id,
            "correlation_id": correlation_id or str(uuid.uuid4()),
            "metadata": metadata or {},
            "environment": getattr(self.settings, "ENVIRONMENT", "development"),
        }

    def _log_local(self, log_entry: Dict[str, Any]):
        """Log local estructurado"""
        log_json = json.dumps(log_entry, ensure_ascii=False)

        if log_entry["level"] == "ERROR":
            self.logger.error(log_json)
        elif log_entry["level"] == "WARNING":
            self.logger.warning(log_json)
        elif log_entry["level"] == "DEBUG":
            self.logger.debug(log_json)
        else:
            self.logger.info(log_json)

    async def _send_to_audit_service(self, log_entry: Dict[str, Any]):
        """
        FUTURO: Envío a audit-service
        Por ahora es un placeholder para la integración futura
        """
        # TODO: Implementar cuando audit-service esté disponible
        # Ejemplo de implementación futura:
        #
        # try:
        #     if (self.service_name != "audit-service" and
        #         hasattr(self.settings, 'AUDIT_SERVICE_URL')):
        #
        #         async with httpx.AsyncClient() as client:
        #             await client.post(
        #                 f"{self.settings.AUDIT_SERVICE_URL}/api/v1/audit/logs",
        #                 json=log_entry,
        #                 timeout=5.0
        #             )
        # except Exception as e:
        #     # Fallback: log del error sin crear bucle infinito
        #     error_entry = self._create_log_entry(
        #         "ERROR",
        #         f"Failed to send log to audit service: {str(e)}",
        #         action="audit_integration_error"
        #     )
        #     self._log_local(error_entry)
        pass

    def info(
        self,
        message: str,
        action: Optional[str] = None,
        user_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        **metadata
    ):
        """Log nivel INFO"""
        log_entry = self._create_log_entry(
            "INFO", message, action, user_id, correlation_id, metadata
        )
        self._log_local(log_entry)
        # Futuro: asyncio.create_task(self._send_to_audit_service(log_entry))

    def error(
        self,
        message: str,
        action: Optional[str] = None,
        user_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        **metadata
    ):
        """Log nivel ERROR"""
        log_entry = self._create_log_entry(
            "ERROR", message, action, user_id, correlation_id, metadata
        )
        self._log_local(log_entry)
        # Futuro: asyncio.create_task(self._send_to_audit_service(log_entry))

    def warning(
        self,
        message: str,
        action: Optional[str] = None,
        user_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        **metadata
    ):
        """Log nivel WARNING"""
        log_entry = self._create_log_entry(
            "WARNING", message, action, user_id, correlation_id, metadata
        )
        self._log_local(log_entry)
        # Futuro: asyncio.create_task(self._send_to_audit_service(log_entry))

    def debug(
        self,
        message: str,
        action: Optional[str] = None,
        user_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        **metadata
    ):
        """Log nivel DEBUG"""
        log_entry = self._create_log_entry(
            "DEBUG", message, action, user_id, correlation_id, metadata
        )
        self._log_local(log_entry)
        # Futuro: asyncio.create_task(self._send_to_audit_service(log_entry))


# Instancia global para uso rápido
def get_logger(service_name: str) -> UnifiedLogger:
    return UnifiedLogger(service_name)
