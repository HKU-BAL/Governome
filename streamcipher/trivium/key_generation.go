package trivium

import (
	"Governome/auxiliary"
	"bytes"
	"encoding/csv"
	"math"
	"math/big"
	"os"
	"strconv"

	"github.com/sp301415/tfhe-go/tfhe"
)

const PointNum = 10

var Batch_Size_Set = [PointNum]int{1, 2, 4, 5, 8, 10, 16, 20, 40, 80}

// This function generate the Key Information held by key holders, along with its public hash value
// keyholderID: 1, 2, ...
func GenerateRawKey(people auxiliary.People, keyholderID int) ([]byte, []byte) {
	rawstr := make([]string, 1)
	rawstr[0] = "Welcome to Governome, key holder" + strconv.Itoa(keyholderID) + " of " + people.Name + "!"
	keyinfo, _ := auxiliary.MimcHash(rawstr, auxiliary.Curve, auxiliary.Mimchashcurve)
	keyhash, _ := auxiliary.MimcHashRaw(keyinfo, auxiliary.Mimchashcurve)
	return keyinfo, keyhash
}

// This function generate the segment key by keyinfo and segmentID
func GenSegmentKey(keyinfo []byte, segmentID int, batch_size int) []int {
	length := ((len(keyinfo)-1)/auxiliary.Mimchashcurve.Size() + 1) * auxiliary.Mimchashcurve.Size()
	keyinfo = auxiliary.PadBytes(keyinfo, length)

	batchnum := int(math.Ceil(80 / float64(batch_size)))

	// In each batch, we get batch_size bits by mimc(keyinfo | segID * 80 + batchID + 1)
	key := make([]int, 80)
	for k := 0; k < batchnum; k++ {
		testval := segmentID*80 + k + 1
		temp := big.NewInt(int64(testval)).Bytes()
		temp = auxiliary.PadBytes(temp, auxiliary.Mimchashcurve.Size())
		temp = append(keyinfo, temp...)
		subhash, _ := auxiliary.MimcHashRaw(temp, auxiliary.Mimchashcurve)
		hashval := big.NewInt(1).SetBytes(subhash)
		for i := 0; i < batch_size && k*batch_size+i < 80; i++ {
			bigk := big.NewInt(1).And(big.NewInt(1), hashval)
			key[k*batch_size+i] = int(bigk.Uint64())
			hashval = big.NewInt(1).Rsh(hashval, 1)
		}
	}

	return key
}

// Generate Segment key for zk-snarks
func GenSegmentKeyWithQuo(keyinfo []byte, segmentID int, batch_size int) ([]int, []*big.Int) {
	length := ((len(keyinfo)-1)/auxiliary.Mimchashcurve.Size() + 1) * auxiliary.Mimchashcurve.Size()
	keyinfo = auxiliary.PadBytes(keyinfo, length)

	batchnum := int(math.Ceil(80 / float64(batch_size)))

	// In each batch, we get batch_size bits by mimc(keyinfo | segID * 80 + batchID + 1)
	key := make([]int, 80)
	res := make([]*big.Int, batchnum)
	for k := 0; k < batchnum; k++ {
		testval := segmentID*80 + k + 1
		temp := big.NewInt(int64(testval)).Bytes()
		temp = auxiliary.PadBytes(temp, auxiliary.Mimchashcurve.Size())
		temp = append(keyinfo, temp...)
		subhash, _ := auxiliary.MimcHashRaw(temp, auxiliary.Mimchashcurve)
		hashval := big.NewInt(1).SetBytes(subhash)
		for i := 0; i < batch_size && k*batch_size+i < 80; i++ {
			bigk := big.NewInt(1).And(big.NewInt(1), hashval)
			key[k*batch_size+i] = int(bigk.Uint64())
			hashval = big.NewInt(1).Rsh(hashval, 1)
		}
		res[k] = hashval
	}

	return key, res
}

// Save secret key for tfheb
func Save_SK(enc *tfhe.BinaryEncryptor) {

	os.Mkdir("../../../Key_Information/", os.ModePerm)

	var buf bytes.Buffer
	enc.BaseEncryptor.SecretKey.WriteTo(&buf)
	os.WriteFile("../../../Key_Information/Trivium_SecretKey", buf.Bytes(), 0644)

	// os.Mkdir("../../../Key_Information/", os.ModePerm)
	// file_path := "../../../Key_Information/Trivium_SecretKey.csv"
	// Data := make([][]string, 1)

	// Data[0] = make([]string, len(enc.BaseEncryptor.SecretKey.LWELargeKey.Value))
	// for i := 0; i < len(enc.BaseEncryptor.SecretKey.LWELargeKey.Value); i++ {
	// 	big_val := big.NewInt(1).SetUint64(uint64(enc.BaseEncryptor.SecretKey.LWELargeKey.Value[i]))
	// 	Data[0][i] = big_val.String()
	// }

	// f, _ := os.Create(file_path)

	// w := csv.NewWriter(f)

	// w.WriteAll(Data)
	// w.Flush()
	// f.Close()
}

// Save Public key for tfheb
func Save_PK(pk auxiliary.PublicKey_tfheb) {
	os.Mkdir("../../../Key_Information/", os.ModePerm)
	file_path := "../../../Key_Information/Trivium_PublicKey.csv"
	size := len(pk.B)
	Data := make([][]string, size+1)

	for i := 0; i < size; i++ {
		Data[i] = make([]string, size)
		for j := 0; j < size; j++ {
			big_val := big.NewInt(1).SetUint64(uint64(pk.A[i][j]))
			Data[i][j] = big_val.String()
		}
	}
	Data[size] = make([]string, size)
	for i := 0; i < size; i++ {
		big_val := big.NewInt(1).SetUint64(uint64(pk.B[i]))
		Data[size][i] = big_val.String()
	}

	f, _ := os.Create(file_path)

	w := csv.NewWriter(f)

	w.WriteAll(Data)
	w.Flush()
	f.Close()
}
