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

type HostedCircuit struct {
	Secret_KeyInfo    frontend.Variable                                           `gnark:"kif"`
	Secret_KeyQuo     frontend.Variable                                           `gnark:"kq"`
	Secret_TriviumKey [Batch_size_Trivium]frontend.Variable                       `gnark:"sd"`
	Secret_temp_Key   [Batch_size_Trivium][RingSize_Trivium]frontend.Variable     `gnark:"tsk"`
	Secret_Error0     [Batch_size_Trivium]frontend.Variable                       `gnark:"ea"`
	Secret_Error1     [Batch_size_Trivium][RingSize_Trivium]frontend.Variable     `gnark:"eb"`
	Secret_Quo        [Batch_size_Trivium][RingSize_Trivium + 1]frontend.Variable `gnark:"quo"`
	Batch_ID          frontend.Variable                                           `gnark:",public"`
	ExpectedHash      frontend.Variable                                           `gnark:",public"`
	Ct                [Batch_size_Trivium][RingSize_Trivium + 1]frontend.Variable `gnark:",public"`
}

func Hosted_CheckKey(api frontend.API, kif, batchid, kq frontend.Variable, key [Batch_size_Trivium]frontend.Variable) {
	field, _ := big.NewInt(1).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 0)
	modulus_Trivium := big.NewInt(1).Lsh(big.NewInt(1), Batch_size_Trivium)
	kq_bound_Trivium := big.NewInt(1).Rsh(field, Batch_size_Trivium)

	mimc1, _ := mimc.NewMiMC(api)
	appval := api.Add(batchid, 1)
	mimc1.Write(kif, appval)
	rawkey := mimc1.Sum()

	val := api.Mul(kq, modulus_Trivium)

	var keyval, temp frontend.Variable
	keyval = 0
	temp = 1
	for i := 0; i < Batch_size_Trivium; i++ {
		keyval = api.Add(keyval, api.Mul(temp, key[i]))
		temp = api.Mul(temp, 2)
	}
	val = api.Add(val, keyval)

	api.AssertIsLessOrEqual(kq, kq_bound_Trivium)
	api.AssertIsEqual(rawkey, val)
}

func (circuit *HostedCircuit) Define(api frontend.API) error {
	for i := 0; i < Batch_size_Trivium; i++ {
		Trivium_CheckTFHEError(api, circuit.Secret_Error0[i])
		api.AssertIsBoolean(circuit.Secret_TriviumKey[i])
		for j := 0; j < RingSize_Trivium; j++ {
			Trivium_CheckTFHEError(api, circuit.Secret_Error1[i][j])
			api.AssertIsBoolean(circuit.Secret_temp_Key[i][j])
		}
		for j := 0; j < RingSize_Trivium+1; j++ {
			Trivium_CheckQuo(api, circuit.Secret_Quo[i][j])
		}
	}
	Trivium_CheckHash(api, circuit.Secret_KeyInfo, circuit.ExpectedHash)
	Hosted_CheckKey(api, circuit.Secret_KeyInfo, circuit.Batch_ID, circuit.Secret_KeyQuo, circuit.Secret_TriviumKey)

	for i := 0; i < Batch_size_Trivium; i++ {
		New_ct := Trivium_EncTFHE(api, circuit.Secret_TriviumKey[i], circuit.Secret_Error0[i], circuit.Secret_temp_Key[i],
			circuit.Secret_Error1[i], circuit.Secret_Quo[i])
		for j := 0; j < RingSize_Trivium+1; j++ {
			api.AssertIsEqual(New_ct[j], circuit.Ct[i][j])
		}
	}
	return nil
}

func EncStreamWithPublicKeyWithProveTFHE_Hosted(keyinfo []byte,
	ccs *constraint.ConstraintSystem, proveKey groth16.ProvingKey) ([]tfhe.LWECiphertext[uint32], []groth16.Proof, []witness.Witness) {

	triv_params := tfhe.ParamsBinaryOriginal.Compile()
	pk := trivium.ReadPK(triv_params)
	batchnum := int(math.Ceil(float64(80 / Batch_size_Trivium)))
	assignment := make([]HostedCircuit, batchnum)

	seg_key, kq := trivium.GenKeyHostedModeWithQuo(keyinfo, Batch_size_Trivium)
	seg_key_ct := make([]tfhe.LWECiphertext[uint32], 80)
	expecthash, _ := auxiliary.MimcHashRaw(keyinfo, auxiliary.Mimchashcurve)

	for k := 0; k < batchnum; k++ {
		assignment[k].Batch_ID = k
		assignment[k].Secret_KeyInfo = keyinfo
		assignment[k].Secret_KeyQuo = kq[k]
		assignment[k].ExpectedHash = expecthash
		for i := 0; i < Batch_size_Trivium && k*Batch_size_Trivium+i < 80; i++ {
			ct, spi := auxiliary.EncWithPublicKeyForZKSnarks_tfheb(uint32(seg_key[k*Batch_size_Trivium+i]), pk)
			assignment[k].Secret_TriviumKey[i] = seg_key[k*Batch_size_Trivium+i]
			assignment[k].Secret_Error0[i] = int32(spi.E0)
			for j := 0; j < RingSize_Trivium; j++ {
				assignment[k].Secret_temp_Key[i][j] = spi.TSK[j]
				assignment[k].Secret_Error1[i][j] = int32(spi.E1[j])
			}
			for j := 0; j < RingSize_Trivium+1; j++ {
				assignment[k].Secret_Quo[i][j] = spi.Quo[j]
				assignment[k].Ct[i][j] = ct.Value[j]
			}
			seg_key_ct[k*Batch_size_Trivium+i] = ct
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

// Reconstruct the publicWitness With the SegKey ciphertext and its hash in hosted mode
func ConstructpublicWitnessWithSegKeyHosted(keyhash []byte, seg_key_ct []tfhe.LWECiphertext[uint32]) []witness.Witness {
	batchnum := int(math.Ceil(float64(80 / Batch_size_Trivium)))
	assignment := make([]DefaultCircuit, batchnum)

	for k := 0; k < batchnum; k++ {
		assignment[k].Batch_ID = k
		assignment[k].Secret_KeyInfo = 0
		assignment[k].Secret_KeyQuo = 0
		assignment[k].ExpectedHash = keyhash
		for i := 0; i < Batch_size_Trivium && k*Batch_size_Trivium+i < 80; i++ {
			assignment[k].Secret_TriviumKey[i] = 0
			assignment[k].Secret_Error0[i] = 0
			for j := 0; j < RingSize_Trivium; j++ {
				assignment[k].Secret_temp_Key[i][j] = 0
				assignment[k].Secret_Error1[i][j] = 0
			}
			for j := 0; j < RingSize_Trivium+1; j++ {
				assignment[k].Secret_Quo[i][j] = 0
				assignment[k].Ct[i][j] = seg_key_ct[k*Batch_size_Trivium+i].Value[j]
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
