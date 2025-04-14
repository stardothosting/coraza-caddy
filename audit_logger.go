package coraza

import (
	"github.com/corazawaf/coraza/v3"
	"go.uber.org/zap"
)

type AuditLogger struct {
	logger *zap.Logger
}

func NewAuditLogger(l *zap.Logger) *AuditLogger {
	return &AuditLogger{
		logger: l,
	}
}

func (l *AuditLogger) LogTransaction(tx coraza.Transaction) {
	logEntry := map[string]interface{}{
		"hostname": tx.GetCollection(coraza.RequestHeaders).Get("Host"),
	}

	// Log using structured logging
	l.logger.Info("transaction audit",
		zap.String("hostname", logEntry["hostname"].(string)),
	)
}
