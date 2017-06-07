//Packet generator for TCP and IP
//Change values of TCP header fields
//Still in beta version
//Updates are coming soon for more options to IP, hopefully ethernet too
package packetgen

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	err error
)

//Use this function to create buffer for packets (Ethernet, IP and TCP)
func CreateBuffer(ipLayer layers.IPv4, tcpLayer layers.TCP) gopacket.SerializeBuffer {

	//Ethernet layer with type IPv4
	ethernetLayer := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
		EthernetType: layers.EthernetTypeIPv4,
	}
	//IP layer with type TCP
	ip := layers.IPv4{
		SrcIP:    ipLayer.SrcIP,
		DstIP:    ipLayer.DstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer.SetNetworkLayerForChecksum(&ip)

	opts := gopacket.SerializeOptions{
		FixLengths:       true, //fix lengths based on the payload (data)
		ComputeChecksums: true, //compute checksum based on the payload during serialization
	}
	//serializing the layers to create a packet
	packetBuf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(packetBuf, opts, &ethernetLayer, &ip, &tcpLayer)

	return packetBuf

}

//Slicing the bytes (with payload) and pushing it into 2D array (removing ethernet from the packet flow)
func ByteConversionPayload(buffer1 gopacket.SerializeBuffer, buffer2 gopacket.SerializeBuffer, buffer3 gopacket.SerializeBuffer, buffer4 gopacket.SerializeBuffer, buffer5 gopacket.SerializeBuffer, buffer6 gopacket.SerializeBuffer, buffer7 gopacket.SerializeBuffer, buffer8 gopacket.SerializeBuffer, buffer9 gopacket.SerializeBuffer) [][]byte {

	bytes1 := buffer1.Bytes()
	bytes1WithoutEthernet := bytes1[14:]

	bytes2 := buffer2.Bytes()
	bytes2WithoutEthernet := bytes2[14:]

	bytes3 := buffer3.Bytes()
	bytes3WithoutEthernet := bytes3[14:]

	bytes4 := buffer4.Bytes()
	bytes4WithoutEthernet := bytes4[14:]

	bytes5 := buffer5.Bytes()
	bytes5WithoutEthernet := bytes5[14:]

	bytes6 := buffer6.Bytes()
	bytes6WithoutEthernet := bytes6[14:]

	bytes7 := buffer7.Bytes()
	bytes7WithoutEthernet := bytes7[14:]

	bytes8 := buffer8.Bytes()
	bytes8WithoutEthernet := bytes8[14:]

	bytes9 := buffer9.Bytes()
	bytes9WithoutEthernet := bytes9[14:]

	var finalBytes [][]byte
	finalBytes = append(finalBytes, bytes1WithoutEthernet)
	finalBytes = append(finalBytes, bytes2WithoutEthernet)
	finalBytes = append(finalBytes, bytes3WithoutEthernet)
	finalBytes = append(finalBytes, bytes4WithoutEthernet)
	finalBytes = append(finalBytes, bytes5WithoutEthernet)
	finalBytes = append(finalBytes, bytes6WithoutEthernet)
	finalBytes = append(finalBytes, bytes7WithoutEthernet)
	finalBytes = append(finalBytes, bytes8WithoutEthernet)
	finalBytes = append(finalBytes, bytes9WithoutEthernet)

	return finalBytes
}

//Slicing the bytes and pushing it into 2D array (removing ethernet from the packet flow)
func ByteConversion(buffer1 gopacket.SerializeBuffer, buffer2 gopacket.SerializeBuffer, buffer3 gopacket.SerializeBuffer) [][]byte {

	bytes1 := buffer1.Bytes()
	bytes1WithoutEthernet := bytes1[14:]

	bytes2 := buffer2.Bytes()
	bytes2WithoutEthernet := bytes2[14:]

	bytes3 := buffer3.Bytes()
	bytes3WithoutEthernet := bytes3[14:]

	var finalBytes [][]byte
	finalBytes = append(finalBytes, bytes1WithoutEthernet)
	finalBytes = append(finalBytes, bytes2WithoutEthernet)
	finalBytes = append(finalBytes, bytes3WithoutEthernet)

	return finalBytes

}

//TCP 3-way handshake generator - without payload
//Use this fucntion to generate a flow of TCP packets (without payload)
//Upgrading the function with payload soon
func (p *PacketFlow) GenerateTCPFlow(bytePacket [][]byte) [][]byte {
	//fmt.Println(p.TCPLayer)
	if bytePacket == nil {
		//fmt.Println("GeneratedPackets")
		p.TCPLayer.Seq = p.SequenceNum
		if p.TCPLayer.SYN == true && p.TCPLayer.ACK == false {
			ipLayer2 := p.IPLayer
			ipLayer2.SrcIP = p.IPLayer.DstIP
			ipLayer2.DstIP = p.IPLayer.SrcIP
			tcpLayer2 := p.TCPLayer
			tcpLayer2.SrcPort = p.TCPLayer.DstPort
			tcpLayer2.DstPort = p.TCPLayer.SrcPort
			tcpLayer2.Seq = 0
			tcpLayer2.Ack = p.SequenceNum + 1
			tcpLayer2.SYN = true
			tcpLayer2.ACK = true
			tcpLayer3 := tcpLayer2
			tcpLayer3.SrcPort = p.TCPLayer.SrcPort
			tcpLayer3.DstPort = p.TCPLayer.DstPort
			tcpLayer3.Seq = tcpLayer2.Ack
			tcpLayer3.Ack = tcpLayer2.Seq + 1
			tcpLayer3.ACK = true
			tcpLayer3.SYN = false
			p.Layers[0] = p.TCPLayer
			p.Layers[1] = tcpLayer2
			p.Layers[2] = tcpLayer3

			newLayer := p.Layers[:3]

			buffer1 := CreateBuffer(p.IPLayer, newLayer[0])
			buffer2 := CreateBuffer(ipLayer2, newLayer[1])
			buffer3 := CreateBuffer(p.IPLayer, newLayer[2])

			p.GeneratedFlow = ByteConversion(buffer1, buffer2, buffer3)

			return p.GeneratedFlow

		} else if p.TCPLayer.SYN == true && p.TCPLayer.ACK == true {
			var dummyLayer layers.TCP
			p.TCPLayer.Ack = rand.Uint32()
			tcpLayer3 := p.TCPLayer
			tcpLayer3.SrcPort = p.TCPLayer.DstPort
			tcpLayer3.DstPort = p.TCPLayer.SrcPort
			tcpLayer3.Seq = p.TCPLayer.Ack
			tcpLayer3.Ack = p.TCPLayer.Seq + 1
			tcpLayer3.ACK = true
			tcpLayer3.SYN = false
			p.Layers[0] = p.TCPLayer
			p.Layers[1] = tcpLayer3
			p.Layers[2] = dummyLayer

			buffer1 := CreateBuffer(p.IPLayer, p.Layers[0])
			buffer2 := CreateBuffer(p.IPLayer, p.Layers[1])
			buffer3 := CreateBuffer(p.IPLayer, p.Layers[2])

			p.GeneratedFlow = ByteConversion(buffer1, buffer2, buffer3)[:2]

			return p.GeneratedFlow

		} else if p.TCPLayer.SYN == false && p.TCPLayer.ACK == true {
			var dummyLayer layers.TCP
			p.TCPLayer.Ack = rand.Uint32()
			p.Layers[0] = p.TCPLayer
			p.Layers[1] = dummyLayer
			p.Layers[2] = dummyLayer

			buffer1 := CreateBuffer(p.IPLayer, p.Layers[0])
			buffer2 := CreateBuffer(p.IPLayer, p.Layers[1])
			buffer3 := CreateBuffer(p.IPLayer, p.Layers[2])

			p.GeneratedFlow = ByteConversion(buffer1, buffer2, buffer3)[:1]

			return p.GeneratedFlow

		}
	} else {

		fmt.Println("PacketsOnTheWire")
		for i := 0; i < len(bytePacket); i++ {
			packet := gopacket.NewPacket(bytePacket[i], layers.LayerTypeIPv4, gopacket.Default)

			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				p.SrcIP = ip.SrcIP
				p.DstIP = ip.DstIP
			}

			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				p.Layers[i] = *tcp
				p.SrcPort = tcp.SrcPort
				p.DstPort = tcp.DstPort
				p.SequenceNum = tcp.Seq
				p.Window = tcp.Window
			}
		}
		p.TemplateFlow = bytePacket

		return p.TemplateFlow

	}

	panic("Unreachable")

}

//TCP packet flow generator - with payload
//Use this fucntion to generate a flow of TCP packets
func (p *PacketFlow) GenerateTCPFlowPayload(newPayload string) [][]byte {

	fmt.Println("GeneratedPackets")
	//fmt.Println([]byte(newPayload))
	payloadNumbers := binary.BigEndian.Uint32([]byte(newPayload))
	//fmt.Println(payloadNumbers)
	p.TCPLayer.Seq = p.SequenceNum
	if p.TCPLayer.SYN == true && p.TCPLayer.ACK == false {
		ipLayer2 := p.IPLayer
		ipLayer2.SrcIP = p.IPLayer.DstIP
		ipLayer2.DstIP = p.IPLayer.SrcIP
		tcpLayer2 := p.TCPLayer
		tcpLayer2.SrcPort = p.TCPLayer.DstPort
		tcpLayer2.DstPort = p.TCPLayer.SrcPort
		tcpLayer2.Seq = 0
		tcpLayer2.Ack = p.SequenceNum + 1
		tcpLayer2.SYN = true
		tcpLayer2.ACK = true
		tcpLayer3 := tcpLayer2
		tcpLayer3.SrcPort = p.TCPLayer.SrcPort
		tcpLayer3.DstPort = p.TCPLayer.DstPort
		tcpLayer3.Seq = tcpLayer2.Ack
		tcpLayer3.Ack = tcpLayer2.Seq + 1
		tcpLayer3.ACK = true
		tcpLayer3.SYN = false
		tcpLayer4 := tcpLayer2
		tcpLayer4.ACK = false
		tcpLayer4.SYN = false
		tcpLayer4.Seq = tcpLayer2.Seq + 1
		tcpLayer4.Payload = []byte(newPayload)
		tcpLayer5 := tcpLayer3
		tcpLayer5.Ack = tcpLayer4.Seq + payloadNumbers
		tcpLayer5.SYN = false
		tcpLayer5.ACK = true
		tcpLayer6 := tcpLayer2
		tcpLayer6.Seq = tcpLayer5.Ack
		tcpLayer6.SYN = false
		tcpLayer6.ACK = true
		tcpLayer6.FIN = true
		tcpLayer7 := p.TCPLayer
		tcpLayer7.Seq = 1
		tcpLayer7.Ack = tcpLayer6.Seq + 1
		tcpLayer7.SYN = false
		tcpLayer7.ACK = true
		tcpLayer8 := tcpLayer7
		tcpLayer8.FIN = true
		tcpLayer8.SYN = false
		tcpLayer8.ACK = true
		tcpLayer9 := tcpLayer2
		tcpLayer9.Seq = tcpLayer8.Ack
		tcpLayer9.SYN = false
		tcpLayer9.Ack = tcpLayer8.Seq + 1
		p.Layers[0] = p.TCPLayer
		p.Layers[1] = tcpLayer2
		p.Layers[2] = tcpLayer3
		p.Layers[3] = tcpLayer4
		p.Layers[4] = tcpLayer5
		p.Layers[5] = tcpLayer6
		p.Layers[6] = tcpLayer7
		p.Layers[7] = tcpLayer8
		p.Layers[8] = tcpLayer9

		newLayer := p.Layers[:9]
		// for i, _ := range newLayer {
		// 	fmt.Println(newLayer[i])
		// }

		buffer1 := CreateBuffer(p.IPLayer, newLayer[0])
		buffer2 := CreateBuffer(ipLayer2, newLayer[1])
		buffer3 := CreateBuffer(p.IPLayer, newLayer[2])
		buffer4 := CreateBuffer(ipLayer2, newLayer[3])
		buffer5 := CreateBuffer(p.IPLayer, newLayer[4])
		buffer6 := CreateBuffer(ipLayer2, newLayer[5])
		buffer7 := CreateBuffer(p.IPLayer, newLayer[6])
		buffer8 := CreateBuffer(p.IPLayer, newLayer[7])
		buffer9 := CreateBuffer(ipLayer2, newLayer[8])

		p.GeneratedFlow = ByteConversionPayload(buffer1, buffer2, buffer3, buffer4, buffer5, buffer6, buffer7, buffer8, buffer9)

		return p.GeneratedFlow

	} else if p.TCPLayer.SYN == true && p.TCPLayer.ACK == true {
		var dummyLayer layers.TCP
		p.TCPLayer.Ack = rand.Uint32()
		tcpLayer3 := p.TCPLayer
		tcpLayer3.SrcPort = p.TCPLayer.DstPort
		tcpLayer3.DstPort = p.TCPLayer.SrcPort
		tcpLayer3.Seq = p.TCPLayer.Ack
		tcpLayer3.Ack = p.TCPLayer.Seq + 1
		tcpLayer3.ACK = true
		tcpLayer3.SYN = false
		p.Layers[0] = p.TCPLayer
		p.Layers[1] = tcpLayer3
		p.Layers[2] = dummyLayer

		buffer1 := CreateBuffer(p.IPLayer, p.Layers[0])
		buffer2 := CreateBuffer(p.IPLayer, p.Layers[1])
		buffer3 := CreateBuffer(p.IPLayer, p.Layers[2])

		p.GeneratedFlow = ByteConversion(buffer1, buffer2, buffer3)[:2]

		return p.GeneratedFlow

	} else if p.TCPLayer.SYN == false && p.TCPLayer.ACK == true {
		var dummyLayer layers.TCP
		p.TCPLayer.Ack = rand.Uint32()
		p.Layers[0] = p.TCPLayer
		p.Layers[1] = dummyLayer
		p.Layers[2] = dummyLayer

		buffer1 := CreateBuffer(p.IPLayer, p.Layers[0])
		buffer2 := CreateBuffer(p.IPLayer, p.Layers[1])
		buffer3 := CreateBuffer(p.IPLayer, p.Layers[2])

		p.GeneratedFlow = ByteConversion(buffer1, buffer2, buffer3)[:1]

		return p.GeneratedFlow

	}

	panic("Unreachable")

}

// func (p *Packet) GenerateInvalidTCPFlow() [][]byte {
//
// 	//fmt.Println(p.TCPLayer)
// 	p.TCPLayer.Seq = p.SequenceNum
// 	var invalidLayers [3]layers.TCP
// 	if p.TCPLayer.SYN == true && p.TCPLayer.ACK == false {
//
// 		ipLayer2 := p.IPLayer
// 		ipLayer2.SrcIP = p.IPLayer.DstIP
// 		ipLayer2.DstIP = p.IPLayer.SrcIP
// 		tcpLayer2 := p.TCPLayer
// 		tcpLayer2.SrcPort = p.TCPLayer.DstPort
// 		tcpLayer2.DstPort = p.TCPLayer.SrcPort
// 		tcpLayer2.Seq = rand.Uint32()
// 		tcpLayer2.Ack = p.SequenceNum + 1
// 		tcpLayer2.SYN = true
// 		tcpLayer2.ACK = true
// 		tcpLayer3 := tcpLayer2
// 		tcpLayer3.SrcPort = p.TCPLayer.SrcPort
// 		tcpLayer3.DstPort = p.TCPLayer.DstPort
// 		tcpLayer3.Seq = tcpLayer2.Ack
// 		tcpLayer3.Ack = tcpLayer2.Seq + 1
// 		tcpLayer3.ACK = true
// 		tcpLayer3.SYN = false
// 		invalidLayers[0] = p.TCPLayer
// 		invalidLayers[1] = tcpLayer3
// 		invalidLayers[2] = tcpLayer2
//
// 		buffer1 := CreateBuffer(p.IPLayer, invalidLayers[0])
// 		buffer2 := CreateBuffer(ipLayer2, invalidLayers[1])
// 		buffer3 := CreateBuffer(p.IPLayer, invalidLayers[2])
//
// 		return ByteConversion(buffer1, buffer2, buffer3)
//
// 	} else if p.TCPLayer.SYN == true && p.TCPLayer.ACK == true {
// 		fmt.Println("SynAck")
// 		var dummyLayer layers.TCP
// 		p.TCPLayer.Ack = rand.Uint32()
// 		tcpLayer3 := p.TCPLayer
// 		tcpLayer3.SrcPort = p.TCPLayer.DstPort
// 		tcpLayer3.DstPort = p.TCPLayer.SrcPort
// 		tcpLayer3.Seq = p.TCPLayer.Ack
// 		tcpLayer3.Ack = p.TCPLayer.Seq + 1
// 		tcpLayer3.ACK = true
// 		tcpLayer3.SYN = false
// 		p.Layers[0] = p.TCPLayer
// 		p.Layers[1] = tcpLayer3
// 		p.Layers[2] = dummyLayer
//
// 		buffer1 := CreateBuffer(p.IPLayer, p.Layers[0])
// 		buffer2 := CreateBuffer(p.IPLayer, p.Layers[1])
// 		buffer3 := CreateBuffer(p.IPLayer, p.Layers[2])
//
// 		SlicedArr := ByteConversion(buffer2, buffer1, buffer3)[:2]
//
// 		return SlicedArr
//
// 	} else if p.TCPLayer.SYN == false && p.TCPLayer.ACK == true {
// 		fmt.Println("Ack")
// 		var dummyLayer layers.TCP
// 		p.TCPLayer.Ack = rand.Uint32()
// 		p.Layers[0] = p.TCPLayer
// 		p.Layers[1] = dummyLayer
// 		p.Layers[2] = dummyLayer
//
// 		buffer1 := CreateBuffer(p.IPLayer, p.Layers[0])
// 		buffer2 := CreateBuffer(p.IPLayer, p.Layers[1])
// 		buffer3 := CreateBuffer(p.IPLayer, p.Layers[2])
//
// 		SlicedArr := ByteConversion(buffer1, buffer2, buffer3)[:1]
//
// 		return SlicedArr
//
// 	}
//
// 	panic("Unreachable")
//
// }

//Use this function to create an IP packet (IPv4)
func (p *Packet) GenerateIPPacket(srcIPstr string, dstIPstr string) layers.IPv4 {

	var srcIP, dstIP net.IP

	//IP address of the source
	srcIP = net.ParseIP(srcIPstr)
	if srcIP == nil {
		log.Printf("non-ip target: %q\n", srcIPstr)
	}

	//IP address of the destination
	dstIP = net.ParseIP(dstIPstr)
	if dstIP == nil {
		log.Printf("non-ip target: %q\n", dstIPstr)
	}

	//IP packet header
	p.IPLayer = layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	return p.IPLayer

}

//Use this function to generate a single IP or TCP or a complete packet in both layers
func (p *Packet) GenerateTCPPacket(ip *layers.IPv4, srcPort layers.TCPPort, dstPort layers.TCPPort) layers.TCP {

	//Port number of the source
	srcport := srcPort
	//Port number of the destination
	dstport := dstPort
	//TCP packet header
	p.TCPLayer = layers.TCP{
		SrcPort: srcport,
		DstPort: dstport,
		Window:  1505,
		Urgent:  0,
		Seq:     11050,
		Ack:     0,
		ACK:     false,
		SYN:     false,
		FIN:     false,
		RST:     false,
		URG:     false,
		ECE:     false,
		CWR:     false,
		NS:      false,
		PSH:     false,
	}
	//Checksum cannot be computed without network layer. Set IP protocol to TCP
	p.TCPLayer.SetNetworkLayerForChecksum(ip)
	//IP header buffer for byte data

	return p.TCPLayer

}

//Use ChangeSequenceNumber function to change the sequence number in TCP packet
func (p *Packet) ChangeSequenceNumber(newSeqNum uint32) layers.TCP {

	p.TCPLayer.Seq = newSeqNum

	return p.TCPLayer

}

//Use ChangeAcknowledgementNumber function to change the acknowledgement number in TCP packet
func (p *Packet) ChangeAcknowledgementNumber(newAckNum uint32) layers.TCP {

	p.TCPLayer.Ack = newAckNum

	return p.TCPLayer

}

//Use ChangeWindow function to change the window size in TCP packet
func (p *Packet) ChangeWindow(newWindow uint16) layers.TCP {

	p.TCPLayer.Window = newWindow

	return p.TCPLayer

}

//Use this function to set Syn Flag
func (p *Packet) SetSynTrue() layers.TCP {

	p.TCPLayer.SYN = true
	p.TCPLayer.ACK = false
	p.TCPLayer.FIN = false

	return p.TCPLayer

}

//Use this function to set Syn and Ack Flag
func (p *Packet) SetSynAckTrue() layers.TCP {

	p.TCPLayer.SYN = true
	p.TCPLayer.ACK = true
	p.TCPLayer.FIN = false

	return p.TCPLayer

}

//Use this function to set Ack flag
func (p *Packet) SetAckTrue() layers.TCP {

	p.TCPLayer.SYN = false
	p.TCPLayer.ACK = true
	p.TCPLayer.FIN = false

	return p.TCPLayer

}

//Use this function to get only SYN packet
func (p *PacketFlow) GetSynPackets() [][]byte {

	var newTCPTemplate [][]byte
	if UseCount == 1 {
		for i := 0; i < len(p.TemplateFlow); i++ {
			if p.Layers[i].SYN == true && p.Layers[i].ACK == false && p.Layers[i].FIN == false {

				newTCPTemplate = append(newTCPTemplate, p.TemplateFlow[i])

			}
		}

		return newTCPTemplate

	} else if UseCount == 0 {
		for j := 0; j < len(p.GeneratedFlow); j++ {
			if p.Layers[j].SYN == true && p.Layers[j].ACK == false && p.Layers[j].FIN == false {

				newTCPTemplate = append(newTCPTemplate, p.GeneratedFlow[j])

			}
		}

		return newTCPTemplate

	}
	panic("Unreachable")
}

//Use this function to get only SynAck packet
func (p *PacketFlow) GetSynAckPackets() [][]byte {

	var newTCPTemplate [][]byte
	if UseCount == 1 {
		for i := 0; i < len(p.TemplateFlow); i++ {
			if p.Layers[i].SYN == true && p.Layers[i].ACK == true && p.Layers[i].FIN == false {

				newTCPTemplate = append(newTCPTemplate, p.TemplateFlow[i])

			}

		}

		return newTCPTemplate

	} else if UseCount == 0 {
		for j := 0; j < len(p.GeneratedFlow); j++ {
			if p.Layers[j].SYN == true && p.Layers[j].ACK == true && p.Layers[j].FIN == false {

				newTCPTemplate = append(newTCPTemplate, p.GeneratedFlow[j])

			}
		}

		return newTCPTemplate

	}
	panic("Unreachable")

}

//Use this function to get only Ack packet
func (p *PacketFlow) GetAckPackets() [][]byte {
	var newTCPTemplate [][]byte
	if UseCount == 1 {
		for i := 0; i < len(p.TemplateFlow); i++ {
			if p.Layers[i].SYN == false && p.Layers[i].ACK == true && p.Layers[i].FIN == false {

				newTCPTemplate = append(newTCPTemplate, p.TemplateFlow[i])

			}

		}

		return newTCPTemplate

	} else if UseCount == 0 {
		for j := 0; j < len(p.GeneratedFlow); j++ {
			if p.Layers[j].SYN == false && p.Layers[j].ACK == true && p.Layers[j].FIN == false {

				newTCPTemplate = append(newTCPTemplate, p.GeneratedFlow[j])

			}
		}
		return newTCPTemplate
	}
	panic("Unreachable")
}

//Use this function to get only SynAck packet
func (p *PacketFlow) GetFinPacket() [][]byte {

	var newTCPTemplate [][]byte
	if UseCount == 1 {
		for i := 0; i < len(p.TemplateFlow); i++ {
			if p.Layers[i].SYN == false && p.Layers[i].ACK == true && p.Layers[i].FIN == true {

				newTCPTemplate = append(newTCPTemplate, p.TemplateFlow[i])

			}

		}

		return newTCPTemplate

	} else if UseCount == 0 {
		for j := 0; j < len(p.GeneratedFlow); j++ {
			if p.Layers[j].SYN == false && p.Layers[j].ACK == true && p.Layers[j].FIN == true {

				newTCPTemplate = append(newTCPTemplate, p.GeneratedFlow[j])

			}
		}

		return newTCPTemplate

	}
	panic("Unreachable")

}

//Use this funciton to change the data to carry in packet
func (p *Packet) ChangePayload(newPayload string) layers.TCP {

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	tcpPayloadBuf := gopacket.NewSerializeBuffer()
	payload := gopacket.Payload([]byte(newPayload))
	err = gopacket.SerializeLayers(tcpPayloadBuf, opts, &p.TCPLayer, payload)
	if err != nil {
		panic(err)
	}

	return p.TCPLayer

}

//Use this function to get the checksum
func (p *Packet) GetChecksum() uint16 {

	return p.TCPLayer.Checksum

}
