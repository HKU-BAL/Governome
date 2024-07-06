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

	// In each batch, we get batch_size bits by mimc(keyinfo, segID * 80 + batchID + 1)
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

// In hosted mode, every segment share a same key, but the iv is different
func GenKeyHostedMode(keyinfo []byte, batch_size int) []int {
	length := ((len(keyinfo)-1)/auxiliary.Mimchashcurve.Size() + 1) * auxiliary.Mimchashcurve.Size()
	keyinfo = auxiliary.PadBytes(keyinfo, length)
	batchnum := int(math.Ceil(80 / float64(batch_size)))

	// In each batch, we get batch_size bits by mimc(keyinfo, batchID + 1)
	key := make([]int, 80)
	for k := 0; k < batchnum; k++ {
		testval := k + 1
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

// Generate Hosted key for zk-snarks
func GenKeyHostedModeWithQuo(keyinfo []byte, batch_size int) ([]int, []*big.Int) {
	length := ((len(keyinfo)-1)/auxiliary.Mimchashcurve.Size() + 1) * auxiliary.Mimchashcurve.Size()
	keyinfo = auxiliary.PadBytes(keyinfo, length)

	batchnum := int(math.Ceil(80 / float64(batch_size)))

	// In each batch, we get batch_size bits by mimc(keyinfo, batchID + 1)
	key := make([]int, 80)
	res := make([]*big.Int, batchnum)
	for k := 0; k < batchnum; k++ {
		testval := k + 1
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

// In hosted mode, every segment share a same key, but the iv is different, based on the segmentID
func GenIVHostedMode(segmentID int) []int {
	iv := make([]int, 80)

	temp := big.NewInt(int64(segmentID)).Bytes()
	temp = auxiliary.PadBytes(temp, auxiliary.Mimchashcurve.Size())
	subhash, _ := auxiliary.MimcHashRaw(temp, auxiliary.Mimchashcurve)
	hashval := big.NewInt(1).SetBytes(subhash)
	for i := 0; i < 80; i++ {
		bigk := big.NewInt(1).And(big.NewInt(1), hashval)
		iv[i] = int(bigk.Uint64())
		hashval = big.NewInt(1).Rsh(hashval, 1)
	}
	return iv
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
	dicpath := auxiliary.ReadPath()

	os.MkdirAll(dicpath+"/Key_Information/", os.ModePerm)

	var buf bytes.Buffer
	enc.BaseEncryptor.SecretKey.WriteTo(&buf)
	os.WriteFile(dicpath+"/Key_Information/Trivium_SecretKey", buf.Bytes(), 0644)

}

// Save Public key for tfheb
func Save_PK(pk auxiliary.PublicKey_tfheb) {
	dicpath := auxiliary.ReadPath()
	os.MkdirAll(dicpath+"/Key_Information/", os.ModePerm)
	file_path := dicpath + "/Key_Information/Trivium_PublicKey.csv"
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
