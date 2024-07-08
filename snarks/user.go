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
func SaveR1CS(ccs constraint.ConstraintSystem, option bool) {
	dicpath := auxiliary.ReadPath()
	file_path := dicpath + "/Snarks/R1CSTrivium/R1CS"

	if option {
		file_path = file_path + "_Hosted"
	}

	_, err := os.Stat(file_path)
	if os.IsNotExist(err) {
		var buf bytes.Buffer
		_, _ = ccs.WriteTo(&buf)
		os.MkdirAll(dicpath+"/Snarks/R1CSTrivium/", os.ModePerm)
		os.WriteFile(file_path, buf.Bytes(), 0644)
		fmt.Println("R1CS circuit Saved!")
	}
}

// Generate or Read R1CS circuit
func GenorReadR1CS(WhetherSave, option bool) (ccs constraint.ConstraintSystem) {
	dicpath := auxiliary.ReadPath()
	file_path := dicpath + "/Snarks/R1CSTrivium/R1CS"

	if option {
		file_path = file_path + "_Hosted"
	}

	_, err := os.Stat(file_path)

	if os.IsNotExist(err) {
		if option {
			var circuit HostedCircuit
			ccs, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
			if WhetherSave {
				SaveR1CS(ccs, option)
			}
			return
		} else {
			var circuit DefaultCircuit
			ccs, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
			if WhetherSave {
				SaveR1CS(ccs, option)
			}
			return
		}
	} else {
		var buf bytes.Buffer
		data, _ := os.ReadFile(file_path)
		buf.Write(data)
		ccs = groth16.NewCS(ecc.BN254)
		ccs.ReadFrom(&buf)
		return ccs
	}
}

// Save Setup Keys
func SaveSetupKeys(ProveKey groth16.ProvingKey, VerifyKey groth16.VerifyingKey, option bool) {
	dicpath := auxiliary.ReadPath()

	filepathpk := dicpath + "/Snarks/SetupTrivium/pk"
	filepathvk := dicpath + "/Snarks/SetupTrivium/vk"
	if option {
		filepathpk = filepathpk + "_Hosted"
		filepathvk = filepathvk + "_Hosted"
	}

	_, errpk := os.Stat(filepathpk)
	_, errvk := os.Stat(filepathvk)

	if os.IsNotExist(errpk) {
		os.MkdirAll(dicpath+"/Snarks/SetupTrivium/", os.ModePerm)
		var buf bytes.Buffer
		ProveKey.WriteRawTo(&buf)
		os.WriteFile(filepathpk, buf.Bytes(), 0644)
		fmt.Println("Proving Key Saved!")
	}

	if os.IsNotExist(errvk) {
		os.MkdirAll(dicpath+"/Snarks/SetupTrivium/", os.ModePerm)
		var buf bytes.Buffer
		VerifyKey.WriteRawTo(&buf)
		os.WriteFile(filepathvk, buf.Bytes(), 0644)
		fmt.Println("Verifying Key Saved!")
	}
}

// Generate or Read R1CS circuit
func GenorReadSetup(r1cs constraint.ConstraintSystem, WhetherSave, option bool) (ProveKey groth16.ProvingKey, VerifyKey groth16.VerifyingKey) {
	dicpath := auxiliary.ReadPath()

	filepathpk := dicpath + "/Snarks/SetupTrivium/pk"
	filepathvk := dicpath + "/Snarks/SetupTrivium/vk"
	if option {
		filepathpk = filepathpk + "_Hosted"
		filepathvk = filepathvk + "_Hosted"
	}

	_, errpk := os.Stat(filepathpk)
	_, errvk := os.Stat(filepathvk)

	if os.IsNotExist(errpk) || os.IsNotExist(errvk) {
		ProveKey, VerifyKey, _ = groth16.Setup(r1cs)
		if WhetherSave {
			SaveSetupKeys(ProveKey, VerifyKey, option)
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
func SaveProof(proof []groth16.Proof, people auxiliary.People, keyholder int) {
	dicpath := auxiliary.ReadPath()
	fullpath := dicpath + "/Snarks/ProofTrivium/" + auxiliary.MappingPeopletoFolder(people) + "/" + people.Name + "/Keyholder_" + strconv.Itoa(keyholder) + "/"
	os.MkdirAll(fullpath, os.ModePerm)

	for k := 0; k < len(proof); k++ {
		var buf bytes.Buffer
		proof[k].WriteRawTo(&buf)
		os.WriteFile(fullpath+"BlockID_"+strconv.Itoa(k), buf.Bytes(), 0644)
	}
}

// Read Proofs
func ReadProof(people auxiliary.People, keyholder int, blocksize int) (proof []groth16.Proof) {
	dicpath := auxiliary.ReadPath()

	fullpath := dicpath + "/Snarks/ProofTrivium/" + auxiliary.MappingPeopletoFolder(people) + "/" + people.Name + "/Keyholder_" + strconv.Itoa(keyholder) + "/"

	size := int(math.Ceil(80 / float64(blocksize)))
	proof = make([]groth16.Proof, size)

	for k := 0; k < size; k++ {

		file_path := fullpath + "BlockID_" + strconv.Itoa(k)
		_, err := os.Stat(file_path)

		if os.IsNotExist(err) {
			log.Fatalf("Read failed, err is %+v", err)
		} else {
			var buf bytes.Buffer
			data, _ := os.ReadFile(file_path)
			buf.Write(data)
			proof[k] = groth16.NewProof(ecc.BN254)
			proof[k].ReadFrom(&buf)
		}
	}

	return
}

// Save the segkey with the proof
func SaveSegkey(segkey []tfhe.LWECiphertext[uint32], people auxiliary.People, keyholder int) {
	dicpath := auxiliary.ReadPath()
	fullpath := dicpath + "/Snarks/SegKey/" + auxiliary.MappingPeopletoFolder(people) + "/" + people.Name + "/Keyholder_" + strconv.Itoa(keyholder) + "/"

	os.MkdirAll(fullpath, os.ModePerm)

	for k := 0; k < len(segkey); k++ {
		var buf bytes.Buffer
		segkey[k].WriteTo(&buf)

		os.WriteFile(fullpath+"BitID_"+strconv.Itoa(k), buf.Bytes(), 0644)
	}

}

// Read Segkey Ciphertext from file
func ReadSegKey(people auxiliary.People, keyholder int, params tfhe.Parameters[uint32]) (segkey []tfhe.LWECiphertext[uint32]) {
	dicpath := auxiliary.ReadPath()
	fullpath := dicpath + "/Snarks/SegKey/" + auxiliary.MappingPeopletoFolder(people) + "/" + people.Name + "/Keyholder_" + strconv.Itoa(keyholder) + "/"

	segkey = make([]tfhe.LWECiphertext[uint32], 80)

	for k := 0; k < 80; k++ {

		filepath := fullpath + "BitID_" + strconv.Itoa(k)
		_, err := os.Stat(filepath)

		if os.IsNotExist(err) {
			log.Fatalf("Read failed, err is %+v", err)
		} else {
			var buf bytes.Buffer
			data, _ := os.ReadFile(filepath)
			buf.Write(data)

			for i := 0; i < 80; i++ {
				segkey[i] = tfhe.NewLWECiphertext[uint32](params)
				segkey[i].ReadFrom(&buf)
			}
		}
	}
	return
}

func UserProof(WhetherSave bool, people auxiliary.People, keyholder int, segID int, option bool) {

	var ccs constraint.ConstraintSystem
	if keyholder == 1 {
		ccs = GenorReadR1CS(WhetherSave, option)
	} else {
		ccs = GenorReadR1CS(WhetherSave, !option)
	}

	ProveKey, VerifyKey := GenorReadSetup(ccs, WhetherSave, option)

	keyinfo, _ := trivium.GenerateRawKey(people, keyholder)

	var segkey []tfhe.LWECiphertext[uint32]
	var proof []groth16.Proof
	var publicWitness []witness.Witness

	if option {
		if keyholder == 1 {
			segkey, proof, publicWitness = EncStreamWithPublicKeyWithProveTFHE_Hosted(keyinfo, &ccs, ProveKey)
		} else {
			segkey, proof, publicWitness = EncStreamWithPublicKeyWithProveTFHE_Boolean(keyinfo, segID, &ccs, ProveKey)
		}

	} else {
		if keyholder == 1 {
			segkey, proof, publicWitness = EncStreamWithPublicKeyWithProveTFHE_Boolean(keyinfo, segID, &ccs, ProveKey)
		} else {
			segkey, proof, publicWitness = EncStreamWithPublicKeyWithProveTFHE_Hosted(keyinfo, &ccs, ProveKey)
		}

	}

	if WhetherSave {
		SaveProof(proof, people, keyholder)
		SaveSegkey(segkey, people, keyholder)
	} else {
		for k := 0; k < len(proof); k++ {
			err := groth16.Verify(proof[k], VerifyKey, publicWitness[k])
			if err != nil {
				log.Fatalf("Verification failed, err is %+v", err)
			}
		}
	}

}
