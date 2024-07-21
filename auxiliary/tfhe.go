// Copyright 2024 The University of Hong Kong, Department of Computer Science
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the
//    names of its contributors may be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package auxiliary

import (
	"math"
	"math/rand"

	"github.com/sp301415/tfhe-go/math/csprng"
	"github.com/sp301415/tfhe-go/tfhe"
)

var ParamsToyBoolean = tfhe.ParametersLiteral[uint32]{
	LWEDimension:    4,
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
	g := csprng.NewGaussianSamplerTorus[uint32](enc.Parameters.GLWEStdDev())
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
	g1 := csprng.NewGaussianSamplerTorus[uint32](pk.Params.GLWEStdDev())
	g2 := csprng.NewGaussianSamplerTorus[uint32](pk.Params.LWEStdDev())
	var spi SecretProveInfo_tfheb
	ct = tfhe.NewLWECiphertext(pk.Params)
	N := len(ct.Value) - 1
	spi.TSK = make([]uint32, N)
	for i := 0; i < N; i++ {
		spi.TSK[i] = uint32(rand.Intn(2))
	}
	spi.E1 = LimitSampleSlice_tfheb(g1, N)
	spi.E0 = LimitSample_tfheb(g2)
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
	g1 := csprng.NewGaussianSamplerTorus[uint32](pk.Params.GLWEStdDev())
	g2 := csprng.NewGaussianSamplerTorus[uint32](pk.Params.LWEStdDev())
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
	spi.E1 = LimitSampleSlice_tfheb(g1, N)
	spi.E0 = LimitSample_tfheb(g2)
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
