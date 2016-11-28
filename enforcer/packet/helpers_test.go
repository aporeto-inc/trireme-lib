package packet

import "testing"

func TestIncrementalCsum16(t *testing.T) {

	t.Parallel()

	newCsum11 := incCsum16(0x017f, 60, 1153)
	if newCsum11 != 0xfd39 {
		t.Errorf("Checksum is %04x", newCsum11)
	}

	newCsum12 := incCsum16(0xfd39, 1153, 60)
	if newCsum12 != 0x017f {
		t.Errorf("Checksum is %04x", newCsum12)
	}

	newCsum21 := incCsum16(0xffc3, 60, 1153)
	if newCsum21 != 0xfb7e {
		t.Errorf("Checksum is %04x", newCsum21)
	}

	newCsum22 := incCsum16(0xfb7e, 1153, 60)
	if newCsum22 != 0xffc3 {
		t.Errorf("Checksum is %04x", newCsum22)
	}
}
