// MIT License
//
// (C) Copyright [2021] Hewlett Packard Enterprise Development LP
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

package http_logger

import (
	"fmt"
	"go.uber.org/zap"
	"strings"
)

// Custom logger interface for retryablehttp to marshal their messages into the correct level of output.

type HTTPLogger struct {
	logger     *zap.Logger
}

func NewHTTPLogger(parentLogger *zap.Logger) *HTTPLogger {
	return &HTTPLogger{
		logger: parentLogger,
	}
}

func (logger *HTTPLogger) Printf(format string, args ...interface{}) {
	originalMessage := fmt.Sprintf(format, args...)

	if strings.HasPrefix(originalMessage, "[DEBUG]") {
		logger.logger.Debug(strings.TrimSpace(strings.TrimPrefix(originalMessage, "[DEBUG]")))
	} else if strings.HasPrefix(originalMessage, "[ERR]") {
		logger.logger.Error(strings.TrimSpace(strings.TrimPrefix(originalMessage, "[ERR]")))
	} else {
		logger.logger.Info(strings.TrimSpace(originalMessage))
	}
}
