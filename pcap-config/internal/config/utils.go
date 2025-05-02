package config

import "github.com/knadh/koanf/v2"

func isValidUint16(
	value *int,
) bool {
	return *value >= 0 && *value <= 0xFFFF
}

func t_uint16(
	ktx *koanf.Koanf,
	path *string,
) uint16 {
	rawValue := ktx.Int(*path)
	if isValidUint16(&rawValue) {
		return uint16(rawValue)
	}
	return 0
}

func t_uint16s(
	ktx *koanf.Koanf,
	path *string,
) []uint16 {
	rawValues := ktx.Ints(*path)
	values := []uint16{}
	for _, rawValue := range rawValues {
		if isValidUint16(&rawValue) {
			values = append(values, uint16(rawValue))
		}
	}
	return values
}
