package coraza

import (
	"github.com/corazawaf/coraza/v3/types"
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

func (l *AuditLogger) LogTransaction(tx types.Transaction) {
	hostname := tx.GetRequestHeader("Host")
	logEntry := map[string]interface{}{
		"hostname": hostname,
	}

	// Log using structured logging
	l.logger.Info("transaction audit",
		zap.String("hostname", hostname),
	)
}
