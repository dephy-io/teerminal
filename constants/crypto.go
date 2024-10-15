package constants

const DerivationPrefix = "_derive_"
const DeviceRootKey = "device_root_key_"
const DeviceEnrollmentKey = "DEPHY_ID_SIGNED_MESSAGE:"

const MaxKvLength = 1024 * 3
const MaxKvEntries = 256 - 8 // 8 reserved for metadata

var TeePlatformVersion = []byte{0x00, 0x00, 0x01, 0x00}
