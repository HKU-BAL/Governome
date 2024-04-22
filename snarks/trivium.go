package snarks

import (
	"Governome/auxiliary"
	"Governome/streamcipher/trivium"
	"bytes"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/sp301415/tfhe-go/tfhe"
)

const (
	Batch_size_Trivium  = 1
	RingSize_Trivium    = 630
	Scale_F_Trivium     = 1 << 29
	bound_2_32          = 1 << 32
	Error_bound_Trivium = 786432
	Full_size_Trivium   = 288
)

type TriviumCircuit struct {
	Secret_KeyInfo    frontend.Variable                                           `gnark:"kif"`
	Secret_KeyQuo     frontend.Variable                                           `gnark:"kq"`
	Secret_TriviumKey [Batch_size_Trivium]frontend.Variable                       `gnark:"sd"`
	Secret_temp_Key   [Batch_size_Trivium][RingSize_Trivium]frontend.Variable     `gnark:"tsk"`
	Secret_Error0     [Batch_size_Trivium]frontend.Variable                       `gnark:"ea"`
	Secret_Error1     [Batch_size_Trivium][RingSize_Trivium]frontend.Variable     `gnark:"eb"`
	Secret_Quo        [Batch_size_Trivium][RingSize_Trivium + 1]frontend.Variable `gnark:"quo"`
	Seg_ID            frontend.Variable                                           `gnark:",public"`
	Batch_ID          frontend.Variable                                           `gnark:",public"`
	ExpectedHash      frontend.Variable                                           `gnark:",public"`
	Ct                [Batch_size_Trivium][RingSize_Trivium + 1]frontend.Variable `gnark:",public"`
}

func Trivium_Scale(api frontend.API, val frontend.Variable) frontend.Variable {
	temp := api.Sub(1, val)
	temp = api.Mul(temp, 7)   // 0 -> 7; 1 -> 0
	temp = api.Add(temp, val) // 0 -> 7; 1 -> 1
	return api.Mul(temp, Scale_F_Trivium)
}

func Trivium_EncTFHE(api frontend.API, m, e0 frontend.Variable, tsk, e1 [RingSize_Trivium]frontend.Variable, quo [RingSize_Trivium + 1]frontend.Variable) (ct [RingSize_Trivium + 1]frontend.Variable) {
	triv_params := tfhe.ParamsBinaryOriginal.Compile()
	pk := trivium.ReadPK(triv_params)
	large_m := Trivium_Scale(api, m)
	ct[0] = api.Add(large_m, e0)

	for i := 0; i < RingSize_Trivium; i++ {
		temp := api.Mul(tsk[i], pk.B[i])
		ct[0] = api.Sub(ct[0], temp)
	}

	for i := 0; i < RingSize_Trivium; i++ {
		ct[i+1] = api.Add(e1[i], 0)
	}

	for i := 0; i < RingSize_Trivium; i++ {
		for j := 0; j < RingSize_Trivium; j++ {
			temp := api.Mul(tsk[i], pk.A[i][j])
			ct[j+1] = api.Add(ct[j+1], temp)
		}
	}

	for i := 0; i < RingSize_Trivium+1; i++ {
		temp := api.Mul(quo[i], bound_2_32)
		ct[i] = api.Sub(ct[i], temp)
	}

	return
}

func Trivium_CheckHash(api frontend.API, data frontend.Variable, expecthash frontend.Variable) {
	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(data)
	hash_result := mimc.Sum()

	api.AssertIsEqual(hash_result, expecthash)
}

func Trivium_CheckKey(api frontend.API, kif, appid, batchid, kq frontend.Variable, key [Batch_size_Trivium]frontend.Variable) {
	field, _ := big.NewInt(1).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 0)
	modulus_Trivium := big.NewInt(1).Lsh(big.NewInt(1), Batch_size_Trivium)
	kq_bound_Trivium := big.NewInt(1).Rsh(field, Batch_size_Trivium)

	mimc1, _ := mimc.NewMiMC(api)
	appval := api.Add(api.Mul(appid, 80), api.Add(batchid, 1))
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

func Trivium_CheckTFHEError(api frontend.API, e frontend.Variable) {
	positive_e := api.Add(e, Error_bound_Trivium)
	api.AssertIsLessOrEqual(positive_e, 2*Error_bound_Trivium)
}

func Trivium_CheckQuo(api frontend.API, q frontend.Variable) {
	api.AssertIsLessOrEqual(api.Add(q, (RingSize_Trivium+1)), 2*(RingSize_Trivium+1))
}

func (circuit *TriviumCircuit) Define(api frontend.API) error {
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
	Trivium_CheckKey(api, circuit.Secret_KeyInfo, circuit.Seg_ID, circuit.Batch_ID, circuit.Secret_KeyQuo, circuit.Secret_TriviumKey)

	for i := 0; i < Batch_size_Trivium; i++ {
		New_ct := Trivium_EncTFHE(api, circuit.Secret_TriviumKey[i], circuit.Secret_Error0[i], circuit.Secret_temp_Key[i],
			circuit.Secret_Error1[i], circuit.Secret_Quo[i])
		for j := 0; j < RingSize_Trivium+1; j++ {
			api.AssertIsEqual(New_ct[j], circuit.Ct[i][j])
		}
	}
	return nil
}

func EncStreamWithPublicKeyWithProveTFHE_Trivium(keyinfo []byte, appid int,
	ccs *constraint.ConstraintSystem, proveKey groth16.ProvingKey) ([]tfhe.LWECiphertext[uint32], []groth16.Proof, []witness.Witness) {
	triv_params := tfhe.ParamsBinaryOriginal.Compile()
	pk := trivium.ReadPK(triv_params)
	batchnum := int(math.Ceil(float64(80 / Batch_size_Trivium)))
	assignment := make([]TriviumCircuit, batchnum)

	seg_key, kq := trivium.GenSegmentKeyWithQuo(keyinfo, appid, Batch_size_Trivium)
	seg_key_ct := make([]tfhe.LWECiphertext[uint32], 80)
	expecthash, _ := auxiliary.MimcHashRaw(keyinfo, auxiliary.Mimchashcurve)

	for k := 0; k < batchnum; k++ {
		assignment[k].Batch_ID = k
		assignment[k].Secret_KeyInfo = keyinfo
		assignment[k].Secret_KeyQuo = kq[k]
		assignment[k].ExpectedHash = expecthash
		assignment[k].Seg_ID = appid
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

// Reconstruct the publicWitness With the SegKey ciphertext and its hash
func ConstructpublicWitnessWithct(appid int, keyhash []byte, seg_key_ct []tfhe.LWECiphertext[uint32]) []witness.Witness {
	batchnum := int(math.Ceil(float64(80 / Batch_size_Trivium)))
	assignment := make([]TriviumCircuit, batchnum)

	for k := 0; k < batchnum; k++ {
		assignment[k].Batch_ID = k
		assignment[k].Secret_KeyInfo = 0
		assignment[k].Secret_KeyQuo = 0
		assignment[k].ExpectedHash = keyhash
		assignment[k].Seg_ID = appid
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

// Save R1CS circuit
func SaveR1CS(ccs constraint.ConstraintSystem, filepath string) {

	_, err := os.Stat(filepath)
	if os.IsNotExist(err) {
		var buf bytes.Buffer
		_, _ = ccs.WriteTo(&buf)
		os.Mkdir("../../../Snarks/", os.ModePerm)
		os.Mkdir("../../../Snarks/R1CSTrivium/", os.ModePerm)
		os.WriteFile(filepath, buf.Bytes(), 0644)
		fmt.Println("R1CS circuit Saved!")
	}
}

// Generate or Read R1CS circuit
func GenorReadR1CS(circuit TriviumCircuit) (ccs constraint.ConstraintSystem) {
	filepath := "../../../Snarks/R1CSTrivium/Trivium_circuit_BatchSize_" + strconv.Itoa(Batch_size_Trivium)
	_, err := os.Stat(filepath)

	if os.IsNotExist(err) {
		ccs, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
		return ccs
	} else {
		var buf bytes.Buffer
		data, _ := os.ReadFile(filepath)
		buf.Write(data)
		ccs = groth16.NewCS(ecc.BN254)
		ccs.ReadFrom(&buf)
		return ccs
	}
}

// Save Setup Keys
func SaveSetupKeys(ProveKey groth16.ProvingKey, VerifyKey groth16.VerifyingKey, filepathpk, filepathvk string) {

	_, errpk := os.Stat(filepathpk)
	_, errvk := os.Stat(filepathvk)

	if os.IsNotExist(errpk) {
		os.Mkdir("../../../Snarks/SetupTrivium/", os.ModePerm)
		var buf bytes.Buffer
		ProveKey.WriteRawTo(&buf)
		os.WriteFile("../../../Snarks/SetupTrivium/pk_BatchSize_"+strconv.Itoa(Batch_size_Trivium), buf.Bytes(), 0644)
		fmt.Println("Proving Key Saved!")
	}

	if os.IsNotExist(errvk) {
		os.Mkdir("../../../Snarks/SetupTrivium/", os.ModePerm)
		var buf bytes.Buffer
		VerifyKey.WriteRawTo(&buf)
		os.WriteFile("../../../Snarks/SetupTrivium/vk_BatchSize_"+strconv.Itoa(Batch_size_Trivium), buf.Bytes(), 0644)
		fmt.Println("Verifying Key Saved!")
	}
}

// Generate or Read R1CS circuit
func GenorReadSetup(r1cs constraint.ConstraintSystem) (ProveKey groth16.ProvingKey, VerifyKey groth16.VerifyingKey) {
	filepathpk := "../../../Snarks/SetupTrivium/pk_BatchSize_" + strconv.Itoa(Batch_size_Trivium)
	filepathvk := "../../../Snarks/SetupTrivium/vk_BatchSize_" + strconv.Itoa(Batch_size_Trivium)

	_, errpk := os.Stat(filepathpk)
	_, errvk := os.Stat(filepathvk)

	if os.IsNotExist(errpk) || os.IsNotExist(errvk) {
		ProveKey, VerifyKey, _ = groth16.Setup(r1cs)
		return
	} else {
		var buf bytes.Buffer

		datapk, _ := os.ReadFile(filepathpk)
		buf.Write(datapk)
		ProveKey = groth16.NewProvingKey(ecc.BN254)
		ProveKey.ReadFrom(&buf)

		buf.Reset()

		datavk, _ := os.ReadFile(filepathvk)
		buf.Write(datavk)
		VerifyKey = groth16.NewVerifyingKey(ecc.BN254)
		VerifyKey.ReadFrom(&buf)

		return
	}
}

// Save Proof and publicWithness
func SaveProofAndWitness(proof []groth16.Proof, publicWitness []witness.Witness, Indivname string, keyholder int, segID int) {
	os.Mkdir("../../../Snarks/ProofTrivium/", os.ModePerm)
	os.Mkdir("../../../Snarks/ProofTrivium/BatchSize_"+strconv.Itoa(Batch_size_Trivium), os.ModePerm)
	os.Mkdir("../../../Snarks/ProofTrivium/BatchSize_"+strconv.Itoa(Batch_size_Trivium)+"/"+Indivname, os.ModePerm)
	os.Mkdir("../../../Snarks/ProofTrivium/BatchSize_"+strconv.Itoa(Batch_size_Trivium)+"/"+Indivname+"/Keyholder_"+strconv.Itoa(keyholder), os.ModePerm)
	os.Mkdir("../../../Snarks/ProofTrivium/BatchSize_"+strconv.Itoa(Batch_size_Trivium)+"/"+Indivname+"/Keyholder_"+strconv.Itoa(keyholder)+
		"/SegID_"+strconv.Itoa(segID), os.ModePerm)
	for k := 0; k < len(proof); k++ {
		var buf bytes.Buffer
		proof[k].WriteRawTo(&buf)

		os.WriteFile("../../../Snarks/ProofTrivium/BatchSize_"+strconv.Itoa(Batch_size_Trivium)+"/"+Indivname+"/Keyholder_"+strconv.Itoa(keyholder)+
			"/SegID_"+strconv.Itoa(segID)+"/BatchID_"+strconv.Itoa(k), buf.Bytes(), 0644)
	}

	os.Mkdir("../../../Snarks/WitnessTrivium/", os.ModePerm)
	os.Mkdir("../../../Snarks/WitnessTrivium/BatchSize_"+strconv.Itoa(Batch_size_Trivium), os.ModePerm)
	os.Mkdir("../../../Snarks/WitnessTrivium/BatchSize_"+strconv.Itoa(Batch_size_Trivium)+"/"+Indivname, os.ModePerm)
	os.Mkdir("../../../Snarks/WitnessTrivium/BatchSize_"+strconv.Itoa(Batch_size_Trivium)+"/"+Indivname+"/Keyholder_"+strconv.Itoa(keyholder), os.ModePerm)
	os.Mkdir("../../../Snarks/WitnessTrivium/BatchSize_"+strconv.Itoa(Batch_size_Trivium)+"/"+Indivname+"/Keyholder_"+strconv.Itoa(keyholder)+
		"/SegID_"+strconv.Itoa(segID), os.ModePerm)
	for k := 0; k < len(publicWitness); k++ {
		var buf bytes.Buffer
		publicWitness[k].WriteTo(&buf)

		os.WriteFile("../../../Snarks/WitnessTrivium/BatchSize_"+strconv.Itoa(Batch_size_Trivium)+"/"+Indivname+"/Keyholder_"+strconv.Itoa(keyholder)+
			"/SegID_"+strconv.Itoa(segID)+"/BatchID_"+strconv.Itoa(k), buf.Bytes(), 0644)
	}
}

// Read Proofs
func ReadProof(Indivname string, keyholder int, segID int, batchsize int) (proof []groth16.Proof) {
	size := int(math.Ceil(80 / float64(batchsize)))
	proof = make([]groth16.Proof, size)
	// publicWitness = make([]witness.Witness, size)
	// var circuit TriviumCircuit

	for k := 0; k < size; k++ {

		filepath := "../../../Snarks/ProofTrivium/BatchSize_" + strconv.Itoa(Batch_size_Trivium) + "/" + Indivname + "/Keyholder_" + strconv.Itoa(keyholder) +
			"/SegID_" + strconv.Itoa(segID) + "/BatchID_" + strconv.Itoa(k)
		_, err := os.Stat(filepath)

		if os.IsNotExist(err) {
			log.Fatalf("Read failed, err is %+v", err)
		} else {
			var buf bytes.Buffer
			data, _ := os.ReadFile(filepath)
			buf.Write(data)
			proof[k] = groth16.NewProof(ecc.BN254)
			proof[k].ReadFrom(&buf)
		}
	}

	// for k := 0; k < size; k++ {

	// 	filepath := "../../../Snarks/WitnessTrivium/BatchSize_" + strconv.Itoa(Batch_size_Trivium) + "/" + Indivname + "/Keyholder_" + strconv.Itoa(keyholder) +
	// 		"/SegID_" + strconv.Itoa(segID) + "/BatchID_" + strconv.Itoa(k)
	// 	_, err := os.Stat(filepath)

	// 	if os.IsNotExist(err) {
	// 		log.Fatalf("Read failed, err is %+v", err)
	// 	} else {
	// 		var buf bytes.Buffer
	// 		data, _ := os.ReadFile(filepath)
	// 		buf.Write(data)

	// 		// temp, _ := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	// 		// publicWitness[k], _ = temp.Public()
	// 		// publicWitness[k], _ = frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	// 		publicWitness[k].ReadFrom(&buf)
	// 	}
	// }
	return
}

// Save the segkey with the proof
func SaveSegkey(segkey []tfhe.LWECiphertext[uint32], Indivname string, keyholder int, segID int) {
	os.Mkdir("../../../Snarks/SegKey/", os.ModePerm)
	os.Mkdir("../../../Snarks/SegKey/BatchSize_"+strconv.Itoa(Batch_size_Trivium), os.ModePerm)
	os.Mkdir("../../../Snarks/SegKey/BatchSize_"+strconv.Itoa(Batch_size_Trivium)+"/"+Indivname, os.ModePerm)
	os.Mkdir("../../../Snarks/SegKey/BatchSize_"+strconv.Itoa(Batch_size_Trivium)+"/"+Indivname+"/Keyholder_"+strconv.Itoa(keyholder), os.ModePerm)
	os.Mkdir("../../../Snarks/SegKey/BatchSize_"+strconv.Itoa(Batch_size_Trivium)+"/"+Indivname+"/Keyholder_"+strconv.Itoa(keyholder)+
		"/SegID_"+strconv.Itoa(segID), os.ModePerm)
	for k := 0; k < len(segkey); k++ {
		var buf bytes.Buffer
		segkey[k].WriteTo(&buf)

		os.WriteFile("../../../Snarks/SegKey/BatchSize_"+strconv.Itoa(Batch_size_Trivium)+"/"+Indivname+"/Keyholder_"+strconv.Itoa(keyholder)+
			"/SegID_"+strconv.Itoa(segID)+"/BatchID_"+strconv.Itoa(k), buf.Bytes(), 0644)
	}

}

// Read Segkey Ciphertext from file
func ReadSegKey(Indivname string, keyholder int, segID int, batchsize int, params tfhe.Parameters[uint32]) (segkey []tfhe.LWECiphertext[uint32]) {
	size := int(math.Ceil(80 / float64(batchsize)))
	segkey = make([]tfhe.LWECiphertext[uint32], 80)

	for k := 0; k < size; k++ {

		filepath := "../../../Snarks/SegKey/BatchSize_" + strconv.Itoa(Batch_size_Trivium) + "/" + Indivname + "/Keyholder_" + strconv.Itoa(keyholder) +
			"/SegID_" + strconv.Itoa(segID) + "/BatchID_" + strconv.Itoa(k)
		_, err := os.Stat(filepath)

		if os.IsNotExist(err) {
			log.Fatalf("Read failed, err is %+v", err)
		} else {
			var buf bytes.Buffer
			data, _ := os.ReadFile(filepath)
			buf.Write(data)

			for i := 0; i < size; i++ {
				if k*batchsize+i < 80 {
					segkey[k*batchsize+i] = tfhe.NewLWECiphertext[uint32](params)
					segkey[k*batchsize+i].ReadFrom(&buf)
				}
			}
		}
	}
	return
}

func UserProof(WhetherSave bool, Indivname string, keyholder int, segID int) {
	var circuit TriviumCircuit
	r1cspath := "../../../Snarks/R1CSTrivium/Trivium_circuit_BatchSize_" + strconv.Itoa(Batch_size_Trivium)
	pkpath := "../../../Snarks/SetupTrivium/pk_BatchSize_" + strconv.Itoa(Batch_size_Trivium)
	vkpath := "../../../Snarks/SetupTrivium/vk_BatchSize_" + strconv.Itoa(Batch_size_Trivium)

	ccs := GenorReadR1CS(circuit)

	if WhetherSave {
		SaveR1CS(ccs, r1cspath)
	}

	ProveKey, VerifyKey := GenorReadSetup(ccs)

	if WhetherSave {
		SaveSetupKeys(ProveKey, VerifyKey, pkpath, vkpath)
	}

	keyinfo, _ := trivium.GenerateRawKey(Indivname, keyholder)

	segkey, proof, publicWitness := EncStreamWithPublicKeyWithProveTFHE_Trivium(keyinfo, segID, &ccs, ProveKey)

	if WhetherSave {
		SaveProofAndWitness(proof, publicWitness, Indivname, keyholder, segID)
		SaveSegkey(segkey, Indivname, keyholder, segID)
	}

	if !WhetherSave {
		for k := 0; k < len(proof); k++ {
			err := groth16.Verify(proof[k], VerifyKey, publicWitness[k])
			if err != nil {
				log.Fatalf("Verification failed, err is %+v", err)
			}
		}
	}

}
