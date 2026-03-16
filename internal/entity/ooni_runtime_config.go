package entity

type OONIRuntimeConfig struct {
	ProbeCC   string
	SinceDays int
	BaseURL   string
	UserAgent string
	TCPPorts  []int
}
