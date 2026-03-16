package classifier

import (
	"errors"
	"math"
	"net"
	"rkn-cocat/internal/checks/common"
	"rkn-cocat/internal/entity"
	"strings"
	"syscall"
)

type ErrorClassifier struct {
	cfg entity.GlobalConfig
}

func New(cfg entity.GlobalConfig) *ErrorClassifier {
	return &ErrorClassifier{cfg: cfg}
}

func (c *ErrorClassifier) ClassifyConnectError(err error, bytesRead int) (string, string, int) {
	fullText := strings.ToLower(err.Error())
	if strings.Contains(fullText, "getaddrinfo failed") ||
		strings.Contains(fullText, "name resolution") ||
		strings.Contains(fullText, "no such host") ||
		strings.Contains(fullText, "nodename nor servname") {
		return common.StatusDNSFail, "DNS-имя не разрешено (NXDOMAIN/сбой резолвера/фильтрация DNS)", bytesRead
	}
	if strings.Contains(fullText, "sslv3_alert") || strings.Contains(fullText, "ssl alert") ||
		(strings.Contains(fullText, "alert") && strings.Contains(fullText, "handshake")) {
		if strings.Contains(fullText, "handshake_failure") || strings.Contains(fullText, "handshake failure") {
			return common.StatusTLSDPI, "TLS alert во время handshake (возможное вмешательство DPI)", bytesRead
		}
		if strings.Contains(fullText, "unrecognized_name") {
			return common.StatusTLSDPI, "TLS alert по SNI (возможная фильтрация по имени)", bytesRead
		}
		if strings.Contains(fullText, "protocol_version") || strings.Contains(fullText, "alert_protocol_version") {
			return common.StatusTLSBlock, "TLS alert по версии протокола (блокировка или несовместимость сервера)", bytesRead
		}
		return common.StatusTLSDPI, "Неожиданный TLS alert на сетевом пути", bytesRead
	}
	if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(fullText, "refused") {
		return common.StatusRefused, "TCP соединение отклонено (порт закрыт, policy deny или фильтр)", bytesRead
	}
	if errors.Is(err, syscall.ECONNRESET) || strings.Contains(fullText, "connection reset") {
		return common.StatusTCPRST, "Сброс (RST) во время установления TLS", bytesRead
	}
	if errors.Is(err, syscall.ECONNABORTED) || strings.Contains(fullText, "connection aborted") {
		return common.StatusTCPAbort, "Соединение прервано во время handshake", bytesRead
	}
	if common.IsTimeoutErr(err) || strings.Contains(fullText, "timed out") {
		return common.StatusTimeout, "Таймаут установления TCP/TLS (потери, фильтрация или недоступный узел)", bytesRead
	}
	if errors.Is(err, syscall.ENETUNREACH) || strings.Contains(fullText, "network is unreachable") {
		return common.StatusNetUnreach, "Маршрут до сети недоступен (локальная сеть/шлюз/маршрутизация)", bytesRead
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || strings.Contains(fullText, "no route to host") {
		return common.StatusHostUnreach, "Маршрут до хоста недоступен (no route to host)", bytesRead
	}
	if strings.Contains(fullText, "x509") || strings.Contains(fullText, "tls") || strings.Contains(fullText, "certificate") {
		return c.ClassifySSLError(err, bytesRead)
	}
	if strings.Contains(fullText, "all connection attempts failed") {
		return common.StatusConnFail, "Все попытки подключения к адресам домена завершились ошибкой", bytesRead
	}
	short := err.Error()
	short = strings.ReplaceAll(short, "\n", " ")
	detail := common.CleanDetail(short)
	if detail == "" {
		detail = "Нераспознанная ошибка подключения"
	}
	return common.StatusConnErr, detail, bytesRead
}

func (c *ErrorClassifier) ClassifyHTTPSConnectError(err error, bytesRead int) (string, string, int) {
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "tls") || strings.Contains(lower, "x509") || strings.Contains(lower, "certificate") {
		return c.ClassifySSLError(err, bytesRead)
	}
	return c.ClassifyConnectError(err, bytesRead)
}

func (c *ErrorClassifier) ClassifyHTTPConnectError(err error, bytesRead int) (string, string, int) {
	lower := strings.ToLower(err.Error())
	if common.IsTimeoutErr(err) || strings.Contains(lower, "timeout") || strings.Contains(lower, "timed out") {
		return common.StatusTimeout, "Таймаут HTTP-подключения/чтения", bytesRead
	}
	if strings.Contains(lower, "no such host") || strings.Contains(lower, "getaddrinfo") || strings.Contains(lower, "name resolution") {
		return common.StatusDNSFail, "DNS не разрешил домен (NXDOMAIN/сбой/фильтрация)", bytesRead
	}
	if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(lower, "refused") {
		return common.StatusRefused, "TCP соединение отклонено удалённой стороной/фильтром", bytesRead
	}
	if errors.Is(err, syscall.ECONNRESET) || strings.Contains(lower, "reset") {
		return common.StatusTCPRST, "Соединение сброшено (RST)", bytesRead
	}
	return c.ClassifyConnectError(err, bytesRead)
}

func (c *ErrorClassifier) ClassifyTLSHandshakeError(err error, bytesRead int) (string, string, int) {
	status, detail, _ := c.ClassifyConnectError(err, bytesRead)
	if status != common.StatusConnErr {
		return status, detail, bytesRead
	}

	tlsStatus, tlsDetail, _ := c.ClassifySSLError(err, bytesRead)
	if tlsStatus == common.StatusSSLErr {
		return status, detail, bytesRead
	}
	return tlsStatus, tlsDetail, bytesRead
}

func (c *ErrorClassifier) ClassifySSLError(err error, bytesRead int) (string, string, int) {
	errorMsg := strings.ToLower(err.Error())
	dpiInterruptionMarkers := []string{
		"eof", "unexpected eof", "eof occurred in violation",
		"operation did not complete", "bad record mac", "decryption failed", "decrypt",
	}
	if common.ContainsAny(errorMsg, dpiInterruptionMarkers) {
		if bytesRead > 0 {
			return common.StatusTLSDPI, "TLS-сессия оборвана во время передачи данных", bytesRead
		}
		return common.StatusTLSDPI, "TLS-сессия оборвана на этапе handshake", bytesRead
	}
	if common.ContainsAny(errorMsg, []string{
		"illegal parameter", "decode error", "decoding error",
		"record overflow", "oversized", "record layer failure", "record_layer_failure",
		"bad key share", "bad_key_share",
	}) {
		if strings.Contains(errorMsg, "bad key share") || strings.Contains(errorMsg, "bad_key_share") {
			return common.StatusSSLErr, "Некорректный key share (часто несовместимость клиента и сервера)", bytesRead
		}
		if strings.Contains(errorMsg, "record layer failure") || strings.Contains(errorMsg, "record_layer_failure") {
			return common.StatusSSLErr, "Ошибка TLS record layer (возможна несовместимость или повреждение трафика)", bytesRead
		}
		return common.StatusTLSDPI, "Аномальный TLS handshake (возможное вмешательство в трафик)", bytesRead
	}
	if strings.Contains(errorMsg, "unrecognized name") || strings.Contains(errorMsg, "unrecognized_name") {
		return common.StatusTLSDPI, "Срабатывание по SNI (возможная блокировка по имени домена)", bytesRead
	}
	if strings.Contains(errorMsg, "alert handshake") || strings.Contains(errorMsg, "sslv3_alert_handshake") {
		return common.StatusTLSDPI, "TLS handshake alert от узла на пути", bytesRead
	}
	if strings.Contains(errorMsg, "handshake") {
		if strings.Contains(errorMsg, "unexpected") {
			return common.StatusTLSDPI, "Неожиданный handshake ответ (возможное вмешательство)", bytesRead
		}
		if strings.Contains(errorMsg, "failure") {
			return common.StatusTLSDPI, "Handshake failure (возможна фильтрация/подмена TLS)", bytesRead
		}
	}
	if strings.Contains(errorMsg, "wrong version number") {
		return common.StatusTLSDPI, "Получен не-TLS ответ на TLS-порт", bytesRead
	}
	if strings.Contains(errorMsg, "certificate") || strings.Contains(errorMsg, "x509") {
		if strings.Contains(errorMsg, "unknown authority") || strings.Contains(errorMsg, "unknown ca") {
			return common.StatusTLSMITM, "Сертификат от недоверенного CA (MITM, прокси или ошибка сервера)", bytesRead
		}
		if strings.Contains(errorMsg, "self-signed") || strings.Contains(errorMsg, "self signed") {
			return common.StatusTLSMITM, "Самоподписанный сертификат (MITM, прокси или тестовый сертификат)", bytesRead
		}
		if strings.Contains(errorMsg, "hostname mismatch") || strings.Contains(errorMsg, "name mismatch") {
			return common.StatusTLSMITM, "Имя в сертификате не совпадает с доменом (подмена или misconfig)", bytesRead
		}
		if strings.Contains(errorMsg, "expired") {
			return common.StatusTLSMITM, "Сертификат просрочен (возможна подмена или проблема у сайта)", bytesRead
		}
		if strings.Contains(errorMsg, "verify failed") {
			return common.StatusTLSMITM, "Проверка сертификата не пройдена (MITM/прокси/misconfig)", bytesRead
		}
		return common.StatusSSLCert, "Ошибка проверки сертификата TLS", bytesRead
	}
	if strings.Contains(errorMsg, "cipher") || strings.Contains(errorMsg, "no shared cipher") {
		return common.StatusTLSMITM, "Нет общего набора шифров (возможен MITM или несовместимость)", bytesRead
	}
	if strings.Contains(errorMsg, "version") || strings.Contains(errorMsg, "protocol version") {
		return common.StatusTLSBlock, "Ошибка версии TLS (фильтрация или несовместимость сервера)", bytesRead
	}
	if strings.Contains(errorMsg, "internal error") {
		return common.StatusSSLInt, "Внутренняя ошибка TLS-стека на клиенте или сервере", bytesRead
	}
	if strings.Contains(errorMsg, "handshake") {
		return common.StatusTLSErr, "Общая ошибка TLS handshake (без явных признаков DPI)", bytesRead
	}
	short := common.CleanDetail(err.Error())
	if short == "" {
		short = "Неопознанная TLS/SSL ошибка"
	}
	return common.StatusSSLErr, short, bytesRead
}

func (c *ErrorClassifier) ClassifyReadError(err error, bytesRead int) (string, string, int) {
	kbRead := math.Ceil(float64(bytesRead) / 1024.0)
	fullText := strings.ToLower(err.Error())
	inRange := int(kbRead) >= c.cfg.TCPBlockMinKB && int(kbRead) <= c.cfg.TCPBlockMaxKB
	if errors.Is(err, syscall.ECONNRESET) || strings.Contains(fullText, "connection reset") {
		if inRange {
			return common.StatusTCP1620, "Сброс (RST) в характерном диапазоне объёма", bytesRead
		}
		if kbRead > 0 {
			return common.StatusDPIReset, "Сброс (RST) после начала передачи данных", bytesRead
		}
		return common.StatusTCPRST, "Сброс (RST) до получения полезных данных", bytesRead
	}
	if errors.Is(err, syscall.ECONNABORTED) || strings.Contains(fullText, "connection aborted") {
		if inRange {
			return common.StatusTCP1620, "Прерывание соединения в характерном диапазоне объёма", bytesRead
		}
		if kbRead > 0 {
			return common.StatusDPIAbort, "Прерывание соединения после начала передачи данных", bytesRead
		}
		return common.StatusTCPAbort, "Соединение прервано до получения полезных данных", bytesRead
	}
	if errors.Is(err, syscall.EPIPE) || strings.Contains(fullText, "broken pipe") {
		if inRange {
			return common.StatusTCP1620, "Разрыв канала (broken pipe) в характерном диапазоне объёма", bytesRead
		}
		if kbRead > 0 {
			return common.StatusDPIPipe, "Разрыв канала (broken pipe) после начала передачи данных", bytesRead
		}
		return common.StatusBrokenPipe, "Разрыв канала (broken pipe) до чтения полезных данных", bytesRead
	}
	if strings.Contains(fullText, "peer closed") || strings.Contains(fullText, "connection closed") {
		if inRange {
			return common.StatusTCP1620, "Удалённая сторона закрыла соединение в характерном диапазоне", bytesRead
		}
		if kbRead > 0 {
			return common.StatusDPIClose, "Удалённая сторона закрыла соединение после начала передачи", bytesRead
		}
		return common.StatusPeerClose, "Удалённая сторона закрыла соединение слишком рано", bytesRead
	}
	if strings.Contains(fullText, "incomplete") {
		if inRange {
			return common.StatusTCP1620, "Неполный ответ в характерном диапазоне объёма", bytesRead
		}
		if kbRead > 0 {
			return common.StatusDPITrunc, "Ответ обрезан после начала передачи данных", bytesRead
		}
		return common.StatusIncomplete, "Ответ сервера неполный", bytesRead
	}
	if common.IsTimeoutErr(err) || strings.Contains(fullText, "timeout") || strings.Contains(fullText, "timed out") {
		if inRange {
			return common.StatusTCP1620, "Таймаут в характерном диапазоне объёма данных", bytesRead
		}
		if kbRead > 0 {
			return common.StatusTimeout, "Таймаут чтения после начала передачи данных", bytesRead
		}
		return common.StatusTimeout, "Таймаут чтения ответа", bytesRead
	}
	if inRange {
		return common.StatusTCP1620, "Ошибка в характерном диапазоне объёма данных", bytesRead
	}
	if kbRead > 0 {
		return common.StatusDPIReset, "Ошибка после начала передачи данных", bytesRead
	}
	return common.StatusReadErr, "Ошибка чтения ответа", bytesRead
}

func (c *ErrorClassifier) ClassifyDNSTransportError(err error) (string, string) {
	if err == nil {
		return common.StatusError, "Неизвестная ошибка"
	}

	lower := strings.ToLower(err.Error())
	var dnsErr *net.DNSError
	switch {
	case (errors.As(err, &dnsErr) && dnsErr.IsNotFound) || strings.Contains(lower, "nxdomain") || strings.Contains(lower, "no such host"):
		return common.StatusNXDOMAIN, "Домен не найден"
	case common.IsTimeoutErr(err) || strings.Contains(lower, "timeout") || strings.Contains(lower, "timed out"):
		return common.StatusTimeout, "Таймаут сети/ответа"
	case errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH):
		return common.StatusBlocked, "Соединение отклонено/недоступно"
	case strings.Contains(lower, "refused") || strings.Contains(lower, "reset") || strings.Contains(lower, "unreachable"):
		return common.StatusBlocked, common.CleanDetail(err.Error())
	default:
		detail := common.CleanDetail(err.Error())
		if detail == "" {
			detail = "Нераспознанная сетевая ошибка"
		}
		return common.StatusError, detail
	}
}
