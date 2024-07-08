package trivium

import (
	"Governome/applications"
	"Governome/auxiliary"
	"encoding/csv"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sp301415/tfhe-go/tfhe"
)

type STR struct {
	Repeat1 [8]int
	Repeat2 [8]int
}

type CODIS struct {
	Loci [13]STR
}

type STR_TFHE struct {
	Repeat1 [8]tfhe.LWECiphertext[uint32]
	Repeat2 [8]tfhe.LWECiphertext[uint32]
}

type CODIS_TFHE struct {
	Loci [13]STR_TFHE
}

// Encrypt a CODIS to TFHE with public key
func Enc_CODIS(c CODIS, pk auxiliary.PublicKey_tfheb) (res CODIS_TFHE) {
	for i := 0; i < 13; i++ {
		for j := 0; j < 8; j++ {
			res.Loci[i].Repeat1[j] = auxiliary.EncWithPublicKey_tfheb(uint32(c.Loci[i].Repeat1[j]), pk)
			res.Loci[i].Repeat2[j] = auxiliary.EncWithPublicKey_tfheb(uint32(c.Loci[i].Repeat2[j]), pk)
		}
	}
	return
}

// Encrypt a CODIS to TFHE without key
func Enc_CODIS_Raw(c CODIS, params tfhe.Parameters[uint32]) (res CODIS_TFHE) {
	for i := 0; i < 13; i++ {
		for j := 0; j < 8; j++ {
			res.Loci[i].Repeat1[j] = NewTFHECiphertext(c.Loci[i].Repeat1[j], params)
			res.Loci[i].Repeat2[j] = NewTFHECiphertext(c.Loci[i].Repeat2[j], params)
		}
	}
	return
}

// Decrypt a CODIS in TFHE ciphertext
func Dec_CODIS(c CODIS_TFHE, enc *tfhe.BinaryEncryptor) (res CODIS) {
	for i := 0; i < 13; i++ {
		for j := 0; j < 8; j++ {
			if enc.DecryptLWEBool(c.Loci[i].Repeat1[j]) {
				res.Loci[i].Repeat1[j] = 1
			}

			if enc.DecryptLWEBool(c.Loci[i].Repeat2[j]) {
				res.Loci[i].Repeat2[j] = 1
			}
		}
	}
	return
}

// Compare whether 2 CODIS are equal
func Compare_CODIS_TFHE(cod1, cod2 CODIS_TFHE, eval *tfhe.BinaryEvaluator) tfhe.LWECiphertext[uint32] {
	res := tfhe.NewLWECiphertext[uint32](eval.Parameters)
	res.Value[0] += auxiliary.ScaleConstant_tfheb(1)

	for i := 0; i < 13; i++ {
		for j := 0; j < 8; j++ {
			temp1 := eval.XNOR(cod1.Loci[i].Repeat1[j], cod2.Loci[i].Repeat1[j])
			temp2 := eval.XNOR(cod1.Loci[i].Repeat2[j], cod2.Loci[i].Repeat2[j])
			res = eval.AND(res, temp1)
			res = eval.AND(res, temp2)
		}
	}

	return res
}

// Decrypt Stream ciphertext with TFHE key
func DecCODISCiphertextBySegKey(encrypted_data CODIS_TFHE, triv *Trivium_TFHE, eval *tfhe.BinaryEvaluator) (decrypted_data CODIS_TFHE) {
	eval = eval.ShallowCopy()

	for i := 0; i < 13; i++ {
		for j := 0; j < 8; j++ {
			new_bit := triv.Genbit(eval)
			decrypted_data.Loci[i].Repeat1[j] = eval.XOR(encrypted_data.Loci[i].Repeat1[j], new_bit)
		}
		for j := 0; j < 8; j++ {
			new_bit := triv.Genbit(eval)
			decrypted_data.Loci[i].Repeat2[j] = eval.XOR(encrypted_data.Loci[i].Repeat2[j], new_bit)
		}
	}

	return
}

// Encode the CODIS to trivium form
func Encode_CODIS(cod []applications.CODIS) []CODIS {
	res := make([]CODIS, len(cod))
	for i := 0; i < len(cod); i++ {
		for j := 0; j < 13; j++ {
			for k := 0; k < 8; k++ {
				res[i].Loci[j].Repeat1[k] = 1 & (cod[i].Loci[j].Repeat1 >> k)
				res[i].Loci[j].Repeat2[k] = 1 & (cod[i].Loci[j].Repeat2 >> k)
			}
		}
	}
	return res
}

// Encode the CODIS to trivium form
func Encode_Single_CODIS(cod applications.CODIS) (res CODIS) {
	for j := 0; j < 13; j++ {
		for k := 0; k < 8; k++ {
			res.Loci[j].Repeat1[k] = 1 & (cod.Loci[j].Repeat1 >> k)
			res.Loci[j].Repeat2[k] = 1 & (cod.Loci[j].Repeat2 >> k)
		}
	}
	return res
}

// Decode the CODIS to origin form
func Decode_CODIS(cod []CODIS) []applications.CODIS {
	res := make([]applications.CODIS, len(cod))
	for i := 0; i < len(cod); i++ {
		for j := 0; j < 13; j++ {
			for k := 0; k < 8; k++ {
				res[i].Loci[j].Repeat1 += (cod[i].Loci[j].Repeat1[k] << k)
				res[i].Loci[j].Repeat2 += (cod[i].Loci[j].Repeat2[k] << k)
			}
		}
	}

	return res
}

// Encrypt the CODIS data
func XOR_CODIS(cod CODIS, keyinfo1, keyinfo2 []byte, option bool) CODIS {

	var StreamKey1, StreamKey2, iv []int

	if option {
		StreamKey1 = GenKeyHostedMode(keyinfo1, 1)
		StreamKey2 = GenSegmentKey(keyinfo2, applications.App_id_SearchPerson, 1)
	} else {
		StreamKey1 = GenSegmentKey(keyinfo1, applications.App_id_SearchPerson, 1)
		StreamKey2 = GenKeyHostedMode(keyinfo2, 1)
	}

	iv = GenIVHostedMode(applications.App_id_SearchPerson)

	StreamKey := make([]int, 80)
	for i := 0; i < 80; i++ {
		StreamKey[i] = StreamKey1[i] ^ StreamKey2[i]
	}
	var triv Trivium
	triv.Init(StreamKey, iv)
	var res CODIS
	for i := 0; i < 13; i++ {
		for j := 0; j < 8; j++ {
			new_bit := triv.Genbit()
			res.Loci[i].Repeat1[j] = cod.Loci[i].Repeat1[j] ^ new_bit
		}
		for j := 0; j < 8; j++ {
			new_bit := triv.Genbit()
			res.Loci[i].Repeat2[j] = cod.Loci[i].Repeat2[j] ^ new_bit
		}
	}
	return res
}

// Encrypt the CODIS Data and Save it
func EncAndSaveCODIS_Trivium(option bool) {
	now := time.Now()
	dicpath := auxiliary.ReadPath()
	os.MkdirAll(dicpath+"/EncSTR", os.ModePerm)
	file_name := "EncStr.csv"
	if option {
		file_name = "EncStrHosted.csv"
	}
	file_path := dicpath + "/EncSTR/" + file_name

	data := applications.ReadCODISData()
	cods := Encode_CODIS(data)
	enc_cods := make([]CODIS, len(cods))
	Indivs := auxiliary.ReadIndividuals()
	keyhashset1 := make([]string, len(Indivs))
	keyhashset2 := make([]string, len(Indivs))
	for i := 0; i < len(Indivs); i++ {
		keyinfo1, keyhash1 := GenerateRawKey(Indivs[i], 1)
		keyinfo2, keyhash2 := GenerateRawKey(Indivs[i], 2)
		keyhashset1[i] = "Hash1: " + big.NewInt(1).SetBytes(keyhash1).String()
		keyhashset2[i] = "Hash2: " + big.NewInt(1).SetBytes(keyhash2).String()
		enc_cods[i] = XOR_CODIS(cods[i], keyinfo1, keyinfo2, option)
	}
	new_data := Decode_CODIS(enc_cods)

	N_Data := make([][]string, len(Indivs))

	for i := 0; i < len(Indivs); i++ {
		N_Data[i] = make([]string, 4)
		N_Data[i][0] = keyhashset1[i]
		N_Data[i][1] = keyhashset2[i]
		N_Data[i] = append(N_Data[i], new_data[i].Decode2String()...)
	}

	f, _ := os.Create(file_path)
	w := csv.NewWriter(f)

	w.WriteAll(N_Data)
	w.Flush()
	f.Close()

	fmt.Printf("Finish Encrypt and Save CODIS of "+strconv.Itoa(len(Indivs))+" Individuals in (%s)\n", time.Since(now))

}

// Read the Encrypted CODIS Data
func ReadCODISData(batch_size int, option bool, dicpath string) (res []applications.CODIS, hash1, hash2 [][]byte) {

	Indivs := auxiliary.ReadIndividuals()

	file_name := "EncStr.csv"
	if option {
		file_name = "EncStrHosted.csv"
	}
	file_path := dicpath + "/EncSTR/" + file_name

	path, _ := filepath.Abs(file_path)

	file, _ := os.Open(path)
	defer file.Close()

	res = make([]applications.CODIS, len(Indivs))
	hash1 = make([][]byte, len(Indivs))
	hash2 = make([][]byte, len(Indivs))

	r := csv.NewReader(file)

	for i := 0; i < len(Indivs); i++ {
		row, err := r.Read()
		if err == io.EOF {
			break
		}

		for j := 4; j < 17; j++ {
			temp := strings.Split(row[j], " ")
			res[i].Loci[j-4].Repeat1, _ = strconv.Atoi(temp[1])
			res[i].Loci[j-4].Repeat2, _ = strconv.Atoi(temp[2])
		}

		temp1, _ := big.NewInt(1).SetString(strings.Split(row[0], " ")[1], 0)
		hash1[i] = auxiliary.PadBytes(temp1.Bytes(), auxiliary.Mimchashcurve.Size())
		temp2, _ := big.NewInt(1).SetString(strings.Split(row[1], " ")[1], 0)
		hash2[i] = auxiliary.PadBytes(temp2.Bytes(), auxiliary.Mimchashcurve.Size())
	}
	return
}
