package packet

import "testing"

func TestChecksum(t *testing.T) {

	b := []byte{
		0x45, 0x00, 0x00, 0x3c, 0xe2, 0xce, 0x40, 0x00, 0x40, 0x06, 0xff, 0xc3, 0xac, 0x11, 0x00, 0x05, 0xac, 0x11, 0x00, 0x02,
	}

	csum := checksum(b)
	if csum != 0 {
		t.Errorf("Bad Checksum 0x%04x. Should be zero.", csum)
	}
}

func TestIncrementalCsum16Pkt1(t *testing.T) {

	t.Parallel()

	/* IP Headers to substantiate test below:
	packet1 := []byte{
		0x45, 0x00, 0x04, 0x81, 0xe1, 0x13, 0x40, 0x00, 0x40, 0x06, 0xfd, 0x39, 0xac, 0x11, 0x00, 0x05, 0xac, 0x11, 0x00, 0x02,
	}
	packet2 := []byte{
		0x45, 0x00, 0x00, 0x3c, 0xe1, 0x13, 0x40, 0x00, 0x40, 0x06, 0x01, 0x7f, 0xac, 0x11, 0x00, 0x05, 0xac, 0x11, 0x00, 0x02,
	}

	// Ensure packet1 is valid
	csum1 := checksum(packet1)
	if csum1 != 0 {
		t.Errorf("Bad Checksum 0x%04x. Should be zero.", csum1)
	}

	// Ensure packet2 is valid
	csum2 := checksum(packet2)
	if csum2 != 0 {
		t.Errorf("Bad Checksum 0x%04x. Should be zero.", csum2)
	}
	*/

	// Start with packet2 and change to packet1 with incremental checksum
	newCsum1 := incCsum16(0x017f, 60, 1153)
	if newCsum1 != 0xfd39 {
		t.Errorf("Checksum is %04x", newCsum1)
	}

	// Start with packet1 and change to packet2 with incremental checksum
	newCsum2 := incCsum16(0xfd39, 1153, 60)
	if newCsum2 != 0x017f {
		t.Errorf("Checksum is %04x", newCsum2)
	}
}

func TestIncrementalCsum16Pkt2(t *testing.T) {

	t.Parallel()

	/* IP Headers to substantiate test below:
	packet1 := []byte{
		0x45, 0x00, 0x00, 0x3c, 0xe2, 0xce, 0x40, 0x00, 0x40, 0x06, 0xff, 0xc3, 0xac, 0x11, 0x00, 0x05, 0xac, 0x11, 0x00, 0x02,
	}

	packet2 := []byte{
		0x45, 0x00, 0x04, 0x81, 0xe2, 0xce, 0x40, 0x00, 0x40, 0x06, 0xfb, 0x7e, 0xac, 0x11, 0x00, 0x05, 0xac, 0x11, 0x00, 0x02,
	}

	// Ensure packet1 is valid
	csum1 := checksum(packet1)
	if csum1 != 0 {
		t.Errorf("Bad Checksum 0x%04x. Should be zero.", csum1)
	}

	// Ensure packet2 is valid
	csum2 := checksum(packet2)
	if csum2 != 0 {
		t.Errorf("Bad Checksum 0x%04x. Should be zero.", csum2)
	}
	*/

	// Start with packet2 and change to packet1 with incremental checksum
	newCsum1 := incCsum16(0xffc3, 60, 1153)
	if newCsum1 != 0xfb7e {
		t.Errorf("Checksum is %04x", newCsum1)
	}

	// Start with packet1 and change to packet2 with incremental checksum
	newCsum2 := incCsum16(0xfb7e, 1153, 60)
	if newCsum2 != 0xffc3 {
		t.Errorf("Checksum is %04x", newCsum2)
	}
}
