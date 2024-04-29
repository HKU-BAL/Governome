package snarks

import (
	"Governome/auxiliary"
	"Governome/streamcipher/trivium"
	"bytes"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/sp301415/tfhe-go/tfhe"
)

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
func GenorReadR1CS(WhetherSave, option bool) (ccs constraint.ConstraintSystem) {

	filepath := "../../../Snarks/R1CSTrivium/Trivium_circuit_BlockSize_" + strconv.Itoa(Batch_size_Trivium)

	if option {
		filepath = filepath + "_Hosted"
	}

	_, err := os.Stat(filepath)

	if os.IsNotExist(err) {
		if option {
			var circuit HostedCircuit
			ccs, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
			if WhetherSave {
				SaveR1CS(ccs, filepath)
			}
			return
		} else {
			var circuit DefaultCircuit
			ccs, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
			if WhetherSave {
				SaveR1CS(ccs, filepath)
			}
			return
		}
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
		os.WriteFile(filepathpk, buf.Bytes(), 0644)
		fmt.Println("Proving Key Saved!")
	}

	if os.IsNotExist(errvk) {
		os.Mkdir("../../../Snarks/SetupTrivium/", os.ModePerm)
		var buf bytes.Buffer
		VerifyKey.WriteRawTo(&buf)
		os.WriteFile(filepathvk, buf.Bytes(), 0644)
		fmt.Println("Verifying Key Saved!")
	}
}

// Generate or Read R1CS circuit
func GenorReadSetup(r1cs constraint.ConstraintSystem, WhetherSave, option bool) (ProveKey groth16.ProvingKey, VerifyKey groth16.VerifyingKey) {
	filepathpk := "../../../Snarks/SetupTrivium/pk_BlockSize_" + strconv.Itoa(Batch_size_Trivium)
	filepathvk := "../../../Snarks/SetupTrivium/vk_BlockSize_" + strconv.Itoa(Batch_size_Trivium)
	if option {
		filepathpk = filepathpk + "_Hosted"
		filepathvk = filepathvk + "_Hosted"
	}

	_, errpk := os.Stat(filepathpk)
	_, errvk := os.Stat(filepathvk)

	if os.IsNotExist(errpk) || os.IsNotExist(errvk) {
		ProveKey, VerifyKey, _ = groth16.Setup(r1cs)
		if WhetherSave {
			SaveSetupKeys(ProveKey, VerifyKey, filepathpk, filepathvk)
		}
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
func SaveProof(proof []groth16.Proof, people auxiliary.People, keyholder int, segID int, option bool) {
	fullpath := "../../../Snarks/ProofTrivium/"
	os.Mkdir(fullpath, os.ModePerm)
	fullpath = fullpath + "BlockSize_" + strconv.Itoa(Batch_size_Trivium) + "/"
	os.Mkdir(fullpath, os.ModePerm)
	fullpath = fullpath + auxiliary.MappingPeopletoFolder(people) + "/"
	os.Mkdir(fullpath, os.ModePerm)
	fullpath = fullpath + people.Name + "/"
	os.Mkdir(fullpath, os.ModePerm)
	fullpath = fullpath + "Keyholder_" + strconv.Itoa(keyholder) + "/"
	os.Mkdir(fullpath, os.ModePerm)
	if option {
		fullpath = fullpath + "Seg_Hosted" + "/"
	} else {
		fullpath = fullpath + "SegID_" + strconv.Itoa(segID) + "/"
	}
	os.Mkdir(fullpath, os.ModePerm)
	for k := 0; k < len(proof); k++ {
		var buf bytes.Buffer
		proof[k].WriteRawTo(&buf)
		os.WriteFile(fullpath+"BlockID_"+strconv.Itoa(k), buf.Bytes(), 0644)
	}
}

// Read Proofs
func ReadProof(people auxiliary.People, keyholder int, segID int, batchsize int, option bool) (proof []groth16.Proof) {
	fullpath := "../../../Snarks/ProofTrivium/"
	fullpath = fullpath + "BlockSize_" + strconv.Itoa(Batch_size_Trivium) + "/"
	fullpath = fullpath + auxiliary.MappingPeopletoFolder(people) + "/"
	fullpath = fullpath + people.Name + "/"
	fullpath = fullpath + "Keyholder_" + strconv.Itoa(keyholder) + "/"
	if option {
		fullpath = fullpath + "Seg_Hosted" + "/"
	} else {
		fullpath = fullpath + "SegID_" + strconv.Itoa(segID) + "/"
	}

	size := int(math.Ceil(80 / float64(batchsize)))
	proof = make([]groth16.Proof, size)

	for k := 0; k < size; k++ {

		filepath := fullpath + "BlockID_" + strconv.Itoa(k)
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

	return
}

// Save the segkey with the proof
func SaveSegkey(segkey []tfhe.LWECiphertext[uint32], people auxiliary.People, keyholder int, segID int, option bool) {
	fullpath := "../../../Snarks/SegKey/"
	os.Mkdir(fullpath, os.ModePerm)
	fullpath = fullpath + "BlockSize_" + strconv.Itoa(Batch_size_Trivium) + "/"
	os.Mkdir(fullpath, os.ModePerm)
	fullpath = fullpath + auxiliary.MappingPeopletoFolder(people) + "/"
	os.Mkdir(fullpath, os.ModePerm)
	fullpath = fullpath + people.Name + "/"
	os.Mkdir(fullpath, os.ModePerm)
	fullpath = fullpath + "Keyholder_" + strconv.Itoa(keyholder) + "/"
	os.Mkdir(fullpath, os.ModePerm)
	if option {
		fullpath = fullpath + "Seg_Hosted" + "/"
	} else {
		fullpath = fullpath + "SegID_" + strconv.Itoa(segID) + "/"
	}
	os.Mkdir(fullpath, os.ModePerm)
	for k := 0; k < len(segkey); k++ {
		var buf bytes.Buffer
		segkey[k].WriteTo(&buf)

		os.WriteFile(fullpath+"BlockID_"+strconv.Itoa(k), buf.Bytes(), 0644)
	}

}

// Read Segkey Ciphertext from file
func ReadSegKey(people auxiliary.People, keyholder int, segID int, batchsize int, params tfhe.Parameters[uint32], option bool) (segkey []tfhe.LWECiphertext[uint32]) {
	fullpath := "../../../Snarks/SegKey/"
	fullpath = fullpath + "BlockSize_" + strconv.Itoa(Batch_size_Trivium) + "/"
	fullpath = fullpath + auxiliary.MappingPeopletoFolder(people) + "/"
	fullpath = fullpath + people.Name + "/"
	fullpath = fullpath + "Keyholder_" + strconv.Itoa(keyholder) + "/"
	if option {
		fullpath = fullpath + "Seg_Hosted" + "/"
	} else {
		fullpath = fullpath + "SegID_" + strconv.Itoa(segID) + "/"
	}

	size := int(math.Ceil(80 / float64(batchsize)))
	segkey = make([]tfhe.LWECiphertext[uint32], 80)

	for k := 0; k < size; k++ {

		filepath := fullpath + "BlockID_" + strconv.Itoa(k)
		_, err := os.Stat(filepath)

		if os.IsNotExist(err) {
			log.Fatalf("Read failed, err is %+v", err)
		} else {
			var buf bytes.Buffer
			data, _ := os.ReadFile(filepath)
			buf.Write(data)

			for i := 0; i < batchsize; i++ {
				if k*batchsize+i < 80 {
					segkey[k*batchsize+i] = tfhe.NewLWECiphertext[uint32](params)
					segkey[k*batchsize+i].ReadFrom(&buf)
				}
			}
		}
	}
	return
}

func UserProof(WhetherSave bool, people auxiliary.People, keyholder int, segID int, option bool) {

	ccs := GenorReadR1CS(WhetherSave, option)

	ProveKey, VerifyKey := GenorReadSetup(ccs, WhetherSave, option)

	keyinfo, _ := trivium.GenerateRawKey(people, keyholder)

	var segkey []tfhe.LWECiphertext[uint32]
	var proof []groth16.Proof
	var publicWitness []witness.Witness

	if option {
		segkey, proof, publicWitness = EncStreamWithPublicKeyWithProveTFHE_Hosted(keyinfo, &ccs, ProveKey)
	} else {
		segkey, proof, publicWitness = EncStreamWithPublicKeyWithProveTFHE_Trivium(keyinfo, segID, &ccs, ProveKey)
	}

	if WhetherSave {
		SaveProof(proof, people, keyholder, segID, option)
		SaveSegkey(segkey, people, keyholder, segID, option)
	} else {
		for k := 0; k < len(proof); k++ {
			err := groth16.Verify(proof[k], VerifyKey, publicWitness[k])
			if err != nil {
				log.Fatalf("Verification failed, err is %+v", err)
			}
		}
	}

}
