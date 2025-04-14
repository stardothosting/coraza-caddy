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
	headers := tx.GetRequestHeaders()
	hostname := ""
	if h := headers.Get("Host"); len(h) > 0 {
		hostname = h[0]
	}

	l.logger.Info("transaction audit",
		zap.String("hostname", hostname),
	)
}
