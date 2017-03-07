package packet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
)

type TCPOptions byte

const (
	EndOfOptionsList                  TCPOptions = 0
	NOP                                          = 1
	MSS                                          = 2
	WindowScale                                  = 3
	SackPermitted                                = 4
	Sack                                         = 5
	Echo                                         = 6
	EchoReply                                    = 7
	TimeStamps                                   = 8
	PartialOrderConnectionPermitted              = 9
	PartialOrderServiceProfile                   = 10
	CC                                           = 11
	CCNEW                                        = 12
	CCECHO                                       = 13
	TCPAlternateChecksumRequest                  = 14
	TCPAlternateChecksumData                     = 15
	Skeeter                                      = 16
	Bubba                                        = 17
	TrailerChecksumOption                        = 18
	MD5SignatureOption                           = 19
	SCPSCapabilities                             = 20
	SelectiveNegativeAcknowledgements            = 21
	RecordBoundaries                             = 22
	CorruptionExperienced                        = 23
	SNAP                                         = 24
	Unassigned                                   = 25
	TCPCompressionFilter                         = 26
	QuickStartResponse                           = 27
	UserTimeoutOption                            = 28
	TCPAuthenticationOption                      = 29
	MultipathTCP                                 = 30
	Reserved                                     = 31
	TCPFastopenCookie                            = 34
	ReservedRangeBegin                           = 35
	ReservedRangeEnd                             = 253
	TCPFastopenCookieEXP                         = 254
	AporetoAuthentication                        = 255
)

type tcpOptionsFormat struct {
	kind   TCPOptions
	length int
	data   []byte
}

// 0 - indicates no payload with the option
// -1 - variable length payload -- read from packet while parsing
// >0 - standard header data
var optionsMap = map[TCPOptions]int{
	EndOfOptionsList:                0,
	NOP:                             0,
	MSS:                             4,
	WindowScale:                     3,
	SackPermitted:                   2,
	Sack:                            -1,
	Echo:                            6,
	EchoReply:                       6,
	TimeStamps:                      10,
	PartialOrderConnectionPermitted: 2,
	PartialOrderServiceProfile:      3,
	CC:     6,
	CCNEW:  6,
	CCECHO: 6,
	TCPAlternateChecksumRequest: 3,
	TCPAlternateChecksumData:    -1,
	Skeeter:                     0,
	Bubba:                       0,
	TrailerChecksumOption:             3,
	MD5SignatureOption:                18,
	SCPSCapabilities:                  4,
	SelectiveNegativeAcknowledgements: -1,
	RecordBoundaries:                  2,
	CorruptionExperienced:             2,
	SNAP:                    -1,
	Unassigned:              0,
	TCPCompressionFilter:    0,
	QuickStartResponse:      8,
	UserTimeoutOption:       4,
	TCPAuthenticationOption: 0,
	MultipathTCP:            -1,
	Reserved:                0,
	TCPFastopenCookie:       -1,
	AporetoAuthentication:   4,
	TCPFastopenCookieEXP:    -1,
}

func (p *Packet) parseTCPOption(bytes []byte) {
	var index byte
	options := bytes[TCPOptionPos:p.TCPDataStartBytes()]
	for index < byte(len(options)) {
		if optionsMap[TCPOptions(options[index])] == 0 {

			p.L4TCPPacket.optionsMap[TCPOptions(options[index])] = tcpOptionsFormat{
				kind:   TCPOptions(options[index]),
				length: 0,
				data:   []byte{},
			}
			index = index + 1
		} else if optionsMap[TCPOptions(options[index])] == -1 {
			if options[index+1] == 2 {
				p.L4TCPPacket.optionsMap[TCPOptions(options[index])] = tcpOptionsFormat{
					kind:   TCPOptions(options[index]),
					length: int(options[index+1]),
					data:   []byte{},
				}
			} else {
				p.L4TCPPacket.optionsMap[TCPOptions(options[index])] = tcpOptionsFormat{
					kind:   TCPOptions(options[index]),
					length: int(options[index+1]),
					data:   options[index+2 : (index + options[index+1])],
				}
			}
			index = index + options[index+1]
		} else {

			p.L4TCPPacket.optionsMap[TCPOptions(options[index])] = tcpOptionsFormat{
				kind:   TCPOptions(options[index]),
				length: optionsMap[TCPOptions(options[index])],
				data:   options[index+2 : (index + byte(optionsMap[TCPOptions(options[index])]))],
			}
			index = index + byte(optionsMap[TCPOptions(options[index])])
		}

	}

}

//TCPOptionLength :: accessor function for option payload length
func (p *Packet) TCPOptionLength(option TCPOptions) int {
	return p.L4TCPPacket.optionsMap[option].length
}

func (p *Packet) TCPOption(option TCPOptions) bool {
	_, ok := p.L4TCPPacket.optionsMap[option]
	return ok
}

//TCPOptionData :: accessor function to the slice of data
func (p *Packet) TCPOptionData(option TCPOptions) ([]byte, bool) {
	optionval, ok := p.L4TCPPacket.optionsMap[option]
	if ok {
		return optionval.data, true
	}

	return nil, false

}

//SetOptionData :: Rewrite data for an option that is already present
func (p *Packet) SetTCPOptionData(option TCPOptions, data []byte) {
	_, ok := p.L4TCPPacket.optionsMap[option]
	newoption := []byte{}
	if ok {
		//Option already present
		//Create a new slice with all other options but this one
		for k, v := range p.L4TCPPacket.optionsMap {
			if k == option {
				continue
			}
			newoption = append(newoption, v.data...)
		}
		//Now add the new option with the data
		newoption = append(newoption, data...)
	} else {
		//Option not present just append
		newoption = append(p.L4TCPPacket.tcpOptions, data...)
	}

	p.L4TCPPacket.tcpOptions = newoption
	for len(p.L4TCPPacket.tcpOptions)%4 != 0 {
		p.L4TCPPacket.tcpOptions = append(p.L4TCPPacket.tcpOptions, 1)
	}
}

func (p *Packet) AppendOption(data []byte) []byte {
	return p.L4TCPPacket.tcpOptions //= append(p.L4TCPPacket.tcpOptions, data...)
}
func (p *Packet) GenerateTCPFastOpenCookie() []byte {
	var binSourceIp, binDestIp uint32
	var byteSourceIp, byteDestIp []byte
	key := make([]byte, 16)
	rand.Read(key)
	if len(p.SourceAddress) == 16 {
		binSourceIp = binary.BigEndian.Uint32(p.SourceAddress[12:16])

	} else {
		binSourceIp = binary.BigEndian.Uint32(p.SourceAddress)
	}
	byteSourceIp = make([]byte, 4)
	binary.BigEndian.PutUint32(byteSourceIp, binSourceIp)
	if len(p.SourceAddress) == 16 {
		binDestIp = binary.BigEndian.Uint32(p.DestinationAddress[12:16])
	} else {
		binDestIp = binary.BigEndian.Uint32(p.DestinationAddress)
	}
	byteDestIp = make([]byte, 4)
	binary.BigEndian.PutUint32(byteDestIp, binDestIp)
	//path := []uint32{binSourceIp, binDestIp, 0, 0}
	block, _ := aes.NewCipher(key)
	ciphertext := make([]byte, aes.BlockSize+16)
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)

	plaintext := byteSourceIp
	plaintext = append(plaintext, byteDestIp...)

	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext

}

//WalkTCPOption :: debug function
func (p *Packet) WalkTCPOptions() {
	// fmt.Println("************************")
	// for key, val := range p.L4TCPPacket.optionsMap {
	// 	fmt.Println("$$$$$$$$$")
	// 	fmt.Println(key)
	// 	fmt.Println(val.length)
	// 	fmt.Println(val.data)
	// 	fmt.Println("$$$$$$$$$")
	// }
	// fmt.Println("************************")
}

func (p *Packet) TCPDataOffset() uint8 {
	return p.L4TCPPacket.tcpDataOffset
}
