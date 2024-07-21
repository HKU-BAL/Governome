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

package snarks

import (
	"Governome/auxiliary"
	"Governome/streamcipher/trivium"
	"math"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/sp301415/tfhe-go/tfhe"
)

const (
	Block_Size       = 1
	RingSize_Boolean = 630
	Scale_F_Boolean  = 1 << 29
	bound_2_32       = 1 << 32
	Error_bound_LWE  = 786432
	Error_bound_RLWE = 768
)

type DefaultCircuit struct {
	Secret_KeyInfo    frontend.Variable                                   `gnark:"kif"`
	Secret_KeyQuo     frontend.Variable                                   `gnark:"kq"`
	Secret_TriviumKey [Block_Size]frontend.Variable                       `gnark:"sd"`
	Secret_temp_Key   [Block_Size][RingSize_Boolean]frontend.Variable     `gnark:"tsk"`
	Secret_Error0     [Block_Size]frontend.Variable                       `gnark:"ea"`
	Secret_Error1     [Block_Size][RingSize_Boolean]frontend.Variable     `gnark:"eb"`
	Secret_Quo        [Block_Size][RingSize_Boolean + 1]frontend.Variable `gnark:"quo"`
	Seg_ID            frontend.Variable                                   `gnark:",public"`
	Batch_ID          frontend.Variable                                   `gnark:",public"`
	ExpectedHash      frontend.Variable                                   `gnark:",public"`
	Ct                [Block_Size][RingSize_Boolean + 1]frontend.Variable `gnark:",public"`
}

func Boolean_Scale(api frontend.API, val frontend.Variable) frontend.Variable {
	temp := api.Sub(1, val)
	temp = api.Mul(temp, 7)   // 0 -> 7; 1 -> 0
	temp = api.Add(temp, val) // 0 -> 7; 1 -> 1
	return api.Mul(temp, Scale_F_Boolean)
}

func Boolean_EncTFHE(api frontend.API, m, e0 frontend.Variable, tsk, e1 [RingSize_Boolean]frontend.Variable, quo [RingSize_Boolean + 1]frontend.Variable) (ct [RingSize_Boolean + 1]frontend.Variable) {
	triv_params := tfhe.ParamsBinaryOriginal.Compile()
	pk := trivium.ReadPK(triv_params)
	large_m := Boolean_Scale(api, m)
	ct[0] = api.Add(large_m, e0)

	for i := 0; i < RingSize_Boolean; i++ {
		temp := api.Mul(tsk[i], pk.B[i])
		ct[0] = api.Sub(ct[0], temp)
	}

	for i := 0; i < RingSize_Boolean; i++ {
		ct[i+1] = api.Add(e1[i], 0)
	}

	for i := 0; i < RingSize_Boolean; i++ {
		for j := 0; j < RingSize_Boolean; j++ {
			temp := api.Mul(tsk[i], pk.A[i][j])
			ct[j+1] = api.Add(ct[j+1], temp)
		}
	}

	for i := 0; i < RingSize_Boolean+1; i++ {
		temp := api.Mul(quo[i], bound_2_32)
		ct[i] = api.Sub(ct[i], temp)
	}

	return
}

func Boolean_CheckHash(api frontend.API, data frontend.Variable, expecthash frontend.Variable) {
	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(data)
	hash_result := mimc.Sum()

	api.AssertIsEqual(hash_result, expecthash)
}

func Boolean_CheckKey(api frontend.API, kif, appid, batchid, kq frontend.Variable, key [Block_Size]frontend.Variable) {
	field, _ := big.NewInt(1).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 0)
	modulus := big.NewInt(1).Lsh(big.NewInt(1), Block_Size)
	kq_bound := big.NewInt(1).Rsh(field, Block_Size)

	mimc1, _ := mimc.NewMiMC(api)
	appval := api.Add(api.Mul(appid, 80), api.Add(batchid, 1))
	mimc1.Write(kif, appval)
	rawkey := mimc1.Sum()

	val := api.Mul(kq, modulus)

	var keyval, temp frontend.Variable
	keyval = 0
	temp = 1
	for i := 0; i < Block_Size; i++ {
		keyval = api.Add(keyval, api.Mul(temp, key[i]))
		temp = api.Mul(temp, 2)
	}
	val = api.Add(val, keyval)

	api.AssertIsLessOrEqual(kq, kq_bound)
	api.AssertIsEqual(rawkey, val)
}

func Boolean_CheckLWEError(api frontend.API, e frontend.Variable) {
	positive_e := api.Add(e, Error_bound_LWE)
	api.AssertIsLessOrEqual(positive_e, 2*Error_bound_LWE)
}

func Boolean_CheckRLWEError(api frontend.API, e frontend.Variable) {
	positive_e := api.Add(e, Error_bound_RLWE)
	api.AssertIsLessOrEqual(positive_e, 2*Error_bound_RLWE)
}

func Boolean_CheckQuo(api frontend.API, q frontend.Variable) {
	api.AssertIsLessOrEqual(api.Add(q, (RingSize_Boolean+1)), 2*(RingSize_Boolean+1))
}

func (circuit *DefaultCircuit) Define(api frontend.API) error {
	for i := 0; i < Block_Size; i++ {
		Boolean_CheckLWEError(api, circuit.Secret_Error0[i])
		api.AssertIsBoolean(circuit.Secret_TriviumKey[i])
		for j := 0; j < RingSize_Boolean; j++ {
			Boolean_CheckRLWEError(api, circuit.Secret_Error1[i][j])
			api.AssertIsBoolean(circuit.Secret_temp_Key[i][j])
		}
		for j := 0; j < RingSize_Boolean+1; j++ {
			Boolean_CheckQuo(api, circuit.Secret_Quo[i][j])
		}
	}
	Boolean_CheckHash(api, circuit.Secret_KeyInfo, circuit.ExpectedHash)
	Boolean_CheckKey(api, circuit.Secret_KeyInfo, circuit.Seg_ID, circuit.Batch_ID, circuit.Secret_KeyQuo, circuit.Secret_TriviumKey)

	for i := 0; i < Block_Size; i++ {
		New_ct := Boolean_EncTFHE(api, circuit.Secret_TriviumKey[i], circuit.Secret_Error0[i], circuit.Secret_temp_Key[i],
			circuit.Secret_Error1[i], circuit.Secret_Quo[i])
		for j := 0; j < RingSize_Boolean+1; j++ {
			api.AssertIsEqual(New_ct[j], circuit.Ct[i][j])
		}
	}
	return nil
}

func EncStreamWithPublicKeyWithProveTFHE_Boolean(keyinfo []byte, appid int,
	ccs *constraint.ConstraintSystem, proveKey groth16.ProvingKey) ([]tfhe.LWECiphertext[uint32], []groth16.Proof, []witness.Witness) {
	triv_params := tfhe.ParamsBinaryOriginal.Compile()
	pk := trivium.ReadPK(triv_params)
	batchnum := int(math.Ceil(float64(80 / Block_Size)))
	assignment := make([]DefaultCircuit, batchnum)

	seg_key, kq := trivium.GenSegmentKeyWithQuo(keyinfo, appid, Block_Size)
	seg_key_ct := make([]tfhe.LWECiphertext[uint32], 80)
	expecthash, _ := auxiliary.MimcHashRaw(keyinfo, auxiliary.Mimchashcurve)

	for k := 0; k < batchnum; k++ {
		assignment[k].Batch_ID = k
		assignment[k].Secret_KeyInfo = keyinfo
		assignment[k].Secret_KeyQuo = kq[k]
		assignment[k].ExpectedHash = expecthash
		assignment[k].Seg_ID = appid
		for i := 0; i < Block_Size && k*Block_Size+i < 80; i++ {
			ct, spi := auxiliary.EncWithPublicKeyForZKSnarks_tfheb(uint32(seg_key[k*Block_Size+i]), pk)
			assignment[k].Secret_TriviumKey[i] = seg_key[k*Block_Size+i]
			assignment[k].Secret_Error0[i] = int32(spi.E0)
			for j := 0; j < RingSize_Boolean; j++ {
				assignment[k].Secret_temp_Key[i][j] = spi.TSK[j]
				assignment[k].Secret_Error1[i][j] = int32(spi.E1[j])
			}
			for j := 0; j < RingSize_Boolean+1; j++ {
				assignment[k].Secret_Quo[i][j] = spi.Quo[j]
				assignment[k].Ct[i][j] = ct.Value[j]
			}
			seg_key_ct[k*Block_Size+i] = ct
		}
	}

	proof := make([]groth16.Proof, batchnum)
	publicWitness := make([]witness.Witness, batchnum)

	for k := 0; k < batchnum; k++ {
		witness, _ := frontend.NewWitness(&assignment[k], ecc.BN254.ScalarField())
		publicWitness[k], _ = witness.Public()
		proof[k], _ = groth16.Prove(*ccs, proveKey, witness)
	}

	return seg_key_ct, proof, publicWitness
}

// Reconstruct the publicWitness With the SegKey ciphertext and its hash
func ConstructpublicWitnessWithSegKeyDefault(appid int, keyhash []byte, seg_key_ct []tfhe.LWECiphertext[uint32]) []witness.Witness {
	batchnum := int(math.Ceil(float64(80 / Block_Size)))
	assignment := make([]DefaultCircuit, batchnum)

	for k := 0; k < batchnum; k++ {
		assignment[k].Batch_ID = k
		assignment[k].Secret_KeyInfo = 0
		assignment[k].Secret_KeyQuo = 0
		assignment[k].ExpectedHash = keyhash
		assignment[k].Seg_ID = appid
		for i := 0; i < Block_Size && k*Block_Size+i < 80; i++ {
			assignment[k].Secret_TriviumKey[i] = 0
			assignment[k].Secret_Error0[i] = 0
			for j := 0; j < RingSize_Boolean; j++ {
				assignment[k].Secret_temp_Key[i][j] = 0
				assignment[k].Secret_Error1[i][j] = 0
			}
			for j := 0; j < RingSize_Boolean+1; j++ {
				assignment[k].Secret_Quo[i][j] = 0
				assignment[k].Ct[i][j] = seg_key_ct[k*Block_Size+i].Value[j]
			}
		}
	}

	publicWitness := make([]witness.Witness, batchnum)

	for k := 0; k < batchnum; k++ {
		witness, _ := frontend.NewWitness(&assignment[k], ecc.BN254.ScalarField())
		publicWitness[k], _ = witness.Public()
	}

	return publicWitness
}
