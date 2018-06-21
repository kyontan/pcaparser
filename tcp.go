package pcaparser

//TCP
type TCP struct {
	Header *TCPHeader
	Data   []byte
}

//ParseTCP
func ParseTCP(data []byte) (*TCP, error) {
	t := &TCP{}

	//header
	if len(data) < DefaultTCPHeaderLen {
		return nil, errPacketHeaderTooShort
	}
	th := ParseTCPHeader(data[0:DefaultTCPHeaderLen])
	t.Header = th
	//options
	//Todo: tcp options

	return t, nil
}
