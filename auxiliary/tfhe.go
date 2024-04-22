package auxiliary

import (
	"bytes"
	"math"
	"math/rand"
	"os"

	"github.com/sp301415/tfhe-go/math/csprng"
	"github.com/sp301415/tfhe-go/tfhe"
)

var ParamsToyBoolean = tfhe.ParametersLiteral[uint32]{
	LWEDimension:    3,
	GLWEDimension:   2,
	PolyDegree:      8,
	PolyLargeDegree: 8,
	LWEStdDev:       0.0000000460803851108693,
	GLWEStdDev:      0.0000000000000000002168404344971009,

	BlockSize: 1,

	MessageModulus: 1 << 2,

	BootstrapParameters: tfhe.GadgetParametersLiteral[uint32]{
		Base:  1 << 7,
		Level: 3,
	},
	KeySwitchParameters: tfhe.GadgetParametersLiteral[uint32]{
		Base:  1 << 2,
		Level: 8,
	},

	BootstrapOrder: tfhe.OrderBlindRotateKeySwitch,
}

type PublicKey_tfheb struct {
	A      [][]uint32
	B      []uint32
	Params tfhe.Parameters[uint32]
}

type SecretProveInfo_tfheb struct {
	TSK []uint32
	E1  []uint32
	Quo []int
	E0  uint32
}

// Scale up a value encoded by tfheb
func ScaleConstant_tfheb(val uint32) uint32 {
	if val == 0 {
		val = 7
	} else {
		val = 1
	}
	return val << 29
}

// Sample a value from tfhe-go algorithm
func LimitSample_tfheb(s csprng.GaussianSampler[uint32]) uint32 {
	for {
		rand_val := s.Sample()
		bound := int(math.Round(6 * s.StdDev))
		// fmt.Println(bound)
		if int(rand_val) < bound && int(rand_val) > (-bound) {
			return rand_val
		}
	}
}

// Sample a Slice from tfhe-go algorithm
func LimitSampleSlice_tfheb(s csprng.GaussianSampler[uint32], length int) []uint32 {
	// fmt.Println(s.StdDev)
	res := make([]uint32, length)
	for i := 0; i < length; i++ {
		res[i] = LimitSample_tfheb(s)
	}
	return res
}

// Generate a public key with the Encryptor in tfhe-go
func GenLWEPublicKey_tfheb(enc *tfhe.BinaryEncryptor) (pk PublicKey_tfheb) {
	sk := enc.BaseEncryptor.SecretKey.LWEKey.Value
	g := csprng.NewGaussianSamplerTorus[uint32](enc.Parameters.LWEStdDev())
	N := len(sk)
	pk.A = make([][]uint32, N)
	for i := 0; i < N; i++ {
		pk.A[i] = make([]uint32, N)
	}
	pk.B = LimitSampleSlice_tfheb(g, N)
	u := csprng.NewUniformSampler[uint32]()
	for i := 0; i < N; i++ {
		for j := 0; j < N; j++ {
			pk.A[i][j] = u.Sample()
		}
	}

	for i := 0; i < N; i++ {
		for j := 0; j < N; j++ {
			pk.B[i] += (pk.A[i][j] * sk[j])
		}
	}
	pk.Params = enc.Parameters
	return
}

// Encrypt a value with public key, here input is in the full domain
func EncWithPublicKey_tfheb(val uint32, pk PublicKey_tfheb) (ct tfhe.LWECiphertext[uint32]) {
	g := csprng.NewGaussianSamplerTorus[uint32](pk.Params.LWEStdDev())
	var spi SecretProveInfo_tfheb
	ct = tfhe.NewLWECiphertext(pk.Params)
	N := len(ct.Value) - 1
	spi.TSK = make([]uint32, N)
	for i := 0; i < N; i++ {
		spi.TSK[i] = uint32(rand.Intn(2))
	}
	spi.E1 = LimitSampleSlice_tfheb(g, N)
	spi.E0 = LimitSample_tfheb(g)
	ct.Value[0] = ScaleConstant_tfheb(val) + spi.E0
	for i := 0; i < N; i++ {
		ct.Value[0] -= (spi.TSK[i] * pk.B[i])
	}

	for i := 0; i < N; i++ {
		ct.Value[i+1] = spi.E1[i]
	}

	for i := 0; i < N; i++ {
		for j := 0; j < N; j++ {
			ct.Value[j+1] += (spi.TSK[i] * pk.A[i][j])
		}
	}
	return
}

// Encrypt a value with public key, return with the information for zk-snarks
func EncWithPublicKeyForZKSnarks_tfheb(val uint32, pk PublicKey_tfheb) (ct tfhe.LWECiphertext[uint32], spi SecretProveInfo_tfheb) {
	g := csprng.NewGaussianSamplerTorus[uint32](pk.Params.LWEStdDev())
	ct = tfhe.NewLWECiphertext(pk.Params)
	N := len(ct.Value) - 1
	spi.TSK = make([]uint32, N)
	spi.Quo = make([]int, N+1)
	for i := 0; i < N+1; i++ {
		spi.Quo[i] = 0
	}
	for i := 0; i < N; i++ {
		spi.TSK[i] = uint32(rand.Intn(2))
	}
	spi.E1 = LimitSampleSlice_tfheb(g, N)
	spi.E0 = LimitSample_tfheb(g)
	if int32(spi.E0) < 0 {
		spi.Quo[0] -= 1
	}
	ct.Value[0] = ScaleConstant_tfheb(val) + spi.E0
	if ct.Value[0] < spi.E0 {
		spi.Quo[0]++
	}

	for i := 0; i < N; i++ {
		temp := ct.Value[0] - (spi.TSK[i] * pk.B[i])
		if temp > ct.Value[0] {
			spi.Quo[0] -= 1
		}
		ct.Value[0] = temp
	}

	for i := 0; i < N; i++ {
		ct.Value[i+1] = spi.E1[i]
		if int32(ct.Value[i+1]) < 0 {
			spi.Quo[i+1] -= 1
		}
	}

	for i := 0; i < N; i++ {
		for j := 0; j < N; j++ {
			temp := ct.Value[j+1] + (spi.TSK[i] * pk.A[i][j])
			if temp < ct.Value[j+1] {
				spi.Quo[j+1]++
			}
			ct.Value[j+1] = temp
		}
	}
	return
}

// Save tfhe ciphertext
func SaveCiphertextb(ct tfhe.LWECiphertext[uint32], file_name string) {

	os.Mkdir("../../../TFHE_Ciphertext_Trivium/", os.ModePerm)

	var buf bytes.Buffer
	ct.WriteTo(&buf)
	os.WriteFile("../../../TFHE_Ciphertext_Trivium/"+file_name, buf.Bytes(), 0644)

}

// Read tfhe ciphertext
func ReadCiphertextb(params tfhe.Parameters[uint32], file_name string) (ct tfhe.LWECiphertext[uint32]) {
	var buf bytes.Buffer
	file, _ := os.ReadFile("../../../TFHE_Ciphertext_Trivium/" + file_name)
	buf.Write(file)

	ct.ReadFrom(&buf)
	return
}
