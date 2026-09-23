package derive

import "time"

// FixedSeed00to1f is the 32-byte Ed25519 seed 00..1f used as the
// characterization vector for every seedify-compatible derivation.
var FixedSeed00to1f = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

// BraveGoldenDate is the UTC date used to lock Brave Sync's 25th word.
var BraveGoldenDate = time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

// PolyseedGoldenBirthday is 2024-06-01 00:00 UTC, used to lock a 16-word polyseed.
const PolyseedGoldenBirthday uint64 = 1717200000

// PolyseedEpochBirthday is 2021-11-01 00:00 UTC (calendar start of the polyseed era).
const PolyseedEpochBirthday uint64 = 1635724800

// Golden values captured from github.com/ZenTenApp/seedify v1.36.0 for FixedSeed00to1f.
const (
	GoldenMnemonic24    = "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware"
	GoldenBrave25th     = "funny"
	GoldenPolyseed16    = "lemon ginger rose weasel genre alley ancient area bulk job tenant evil movie van cube pig"
	GoldenPolyseedEpoch = "keen ginger rose weasel genre alley ancient area bulk job tenant evidence move valve crystal pig"

	GoldenNpub    = "npub102xk3gvg50prsrgm76ksy8nh6enrsgwpqgr3hku4g204z364lnns533vq7"
	GoldenNsec    = "nsec1wnrq2ka38vxtsn3j83s3td7xsdlxhrzk8w8qyunykmluk66lz64slqplsa"
	GoldenPubHex  = "7a8d68a188a3c2380d1bf6ad021e77d6663821c102071bdb95429f514755fce7"
	GoldenPrivHex = "74c6055bb13b0cb84e323c6115b7c6837e6b8c563b8e027264b6ffcb6b5f16ab"

	GoldenBitcoin       = "bc1qslk39wvggqa0vl8nd6jckaz54dw3vk45c5w60m"
	GoldenBitcoinCash   = "qptf4pe2u20g8ww73sguex6hsjh6rxcgfc4mkrcz2a"
	GoldenEthereum      = "0xF9297b542BDb5DA50C364f9AE4Cbe1F3933bA40F"
	GoldenSolana        = "5Pobwp6d9ihN9Nz38f87gVCEBFMgipFiSM2VtUhVit6w"
	GoldenTron          = "TQ8xLycC44dA9nnvME3K6X41iMjmR3J1Vz"
	GoldenLitecoin      = "ltc1q0rvyr86d5pf5hlzudx3w8ykee4h5lwqs22v6qx"
	GoldenDogecoin      = "DCz1sQFeqqfqJLwmWEBEjAxJ92Bhxf9gww"
	GoldenCosmos        = "cosmos16yy67pj7ncthhpmfmyascn2qp2al0g0e8j4qgh"
	GoldenStellar       = "GCTO7ULPT5QHXCG2ZRVXUXBFUAJ4AQPFCWRTPAROGCZZ4QD36GKV3JXB"
	GoldenRipple        = "r3u247nGDQcr1JX9fS8s5WY4tVNKK384Zu"
	GoldenSui           = "0x7f96ee80ed7453fdd3b2cad7995da20e4ae5a76bded5015b4d1801bacd7801c9"
	GoldenSilentPayment = "sp1qqtu4m9jlt6yl2mjwst6pp0raqkyjapz50gthr52d0pschtwqany5gq5uryj0tecznmds8xngvnsv4yjg0d6vgdz6e2nsptqr8xt5ffflqqnzrduf"
	GoldenTon           = "UQBmx5RDvDnPuUVcu6F4oBs2m0brTn59RTCVlAELuxxeiVec"

	GoldenMoneroPolyseedPrimary = "42D1qEvgumHa6dZqVqwDusVxUz9PbFGWTUhjGpCkKisBem9xNxCzxbY1QqVaBfAEdJ2cTAWz3ofv4VigE6UZovFX3uqyVv5"
	GoldenMoneroPolyseedSub0    = "883akJfgEmFUmrY1fhKpMAGeyFuvKxmpsDZtmwVPuEGcGjL84ez2sMUGZK1HMZzyvSBZEvxzmWnHYdUxnLcFtDxsG9MkeXY"

	GoldenLegacy25       = "tossed mural diplomat jump peaches gearbox yoga hyper sphere biscuit rated powder upcoming vacation zigzags boxes ornament renting glass gained island bemused alarms bakery ornament"
	GoldenReducedSeedHex = "132d0ca6e9a1f3ae316c12682d132ffa0f1112131415161718191a1b1c1d1e0f"

	GoldenMoneroLegacyPrimary = "49HjJN4ZbLjDFqe3Mus7mPZBE6Q27cRGtPLfyuNejGdYZhvke36zj1xGq5kDCbSCXbc5TLTR7vygzVDYTcgFURLaLe4Gdds"
	GoldenMoneroLegacySub0    = "89JZu9GXu4zavCrprHJBhqe93rCDYAXGS75C8qoi1DKuKQwCfbZMM3tHxwH5H7Mx5ZaTPoHrEcTBEXyKiHYt47L6Q8ar72s"
	GoldenBeldexLegacyPrimary = "bxdX8BhX3i3bqdxkyw9Ph2Ls3C1sCXvQaWhBcQTZ2FfbHgqNBWHYS22FcbXP23wp7NewRx9JuSNHdSNHMHuUo3rv14ptKXWMH"
	GoldenBeldexLegacySub0    = "LXCLvss2tsGavCrprHJBhqe93rCDYAXGS75C8qoi1DKuKQwCfbZMM3tHxwH5H7Mx5ZaTPoHrEcTBEXyKiHYt47L6QD5WBxA"
)
