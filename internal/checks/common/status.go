package common

const (
	StatusOK              = "OK"
	StatusError           = "ERROR"
	StatusGlobalConfigErr = "GlobalConfig ERR"
	StatusBlocked         = "BLOCKED"
	StatusTimeout         = "TIMEOUT"
	StatusRedir           = "REDIR"
	StatusEmpty           = "EMPTY"
	StatusNoData          = "NO_DATA"
	StatusUnknown         = "UNKNOWN"
	StatusConnErr         = "CONN ERR"
	StatusConnFail        = "CONN FAIL"
)

const (
	StatusNXDOMAIN         = "NXDOMAIN"
	StatusSERVFAIL         = "SERVFAIL"
	StatusRefused          = "REFUSED"
	StatusDNSOK            = "DNS OK"
	StatusDNSFail          = "DNS FAIL"
	StatusDNSFake          = "DNS FAKE"
	StatusValidWithDNSHint = "VALID + DNS BLOCK HINT"
	StatusNoErrorAnswer    = "NOERROR+ANSWER"
	StatusNoErrorEmptyView = "NOERROR EMPTY"
	StatusNoErrorEmpty     = "NOERROR_EMPTY"
)

const (
	StatusNoDiff          = "NO DIFF"
	StatusSNIDPI          = "SNI DPI"
	StatusSNIInconclusive = "SNI INCONCLUSIVE"
	StatusISPPage         = "ISP PAGE"
	StatusTLSDPI          = "TLS DPI"
	StatusTLSMITM         = "TLS MITM"
	StatusTLSBlock        = "TLS BLOCK"
	StatusTLSErr          = "TLS ERR"
	StatusSSLCert         = "SSL CERT"
	StatusSSLInt          = "SSL INT"
	StatusSSLErr          = "SSL ERR"
)

const (
	StatusTCPFail          = "TCP FAIL"
	StatusOONITCPFail      = "TCP_FAIL"
	StatusOONITCPReachable = "TCP_REACHABLE"
	StatusTCPRST           = "TCP RST"
	StatusTCPAbort         = "TCP ABORT"
	StatusNetUnreach       = "NET UNREACH"
	StatusHostUnreach      = "HOST UNREACH"
	StatusTCP1620          = "TCP16-20"
)

const (
	StatusDPIReset   = "DPI RESET"
	StatusDPIAbort   = "DPI ABORT"
	StatusDPIPipe    = "DPI PIPE"
	StatusDPIClose   = "DPI CLOSE"
	StatusDPITrunc   = "DPI TRUNC"
	StatusBrokenPipe = "BROKEN PIPE"
	StatusPeerClose  = "PEER CLOSE"
	StatusIncomplete = "INCOMPLETE"
	StatusReadErr    = "READ ERR"
)

const (
	StatusSweepPass    = "SWEEP PASS"
	StatusSweepBlock   = "SWEEP BLOCK"
	StatusSweepOutside = "SWEEP OUTSIDE"
	StatusSweepErr     = "SWEEP ERR"
	StatusSweepShort   = "SWEEP SHORT"
	StatusSweepBreak   = "SWEEP BREAK"
	StatusAllOK        = "ALL OK"
	StatusPartial      = "PARTIAL"
	StatusMixed        = "MIXED"
	StatusValid        = "VALID"
)
