package pcaparser

//Packet
type Packet struct {
	Header *PacketHeader
	Data   interface{}
}

//ParsePacket
func ParsePacket(pcap *Pcap) (*Packet, error) {

	p := new(Packet)
	//get 14-bytes
	headerData := make([]byte, PacketHeaderLen)
	_, err := pcap.r.Read(headerData)
	if err != nil {
		return nil, err
	}

	//header
	ph, err := ParsePacketHeader(pcap, headerData)
	if err != nil {
		return nil, err
	}
	p.Header = ph

	//data
	data := make([]byte, ph.CapLen)
	_, err = pcap.r.Read(data)
	if err != nil {
		return nil, err
	}
	//ethernet
	e, err := ParseEthernet(data)
	if err != nil {
		return nil, err
	}
	p.Data = e
	return p, nil
}
