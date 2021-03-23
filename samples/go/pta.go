/*
 *
 * % go build pta.go
 * go: downloading github.com/spacemonkeygo/openssl v0.0.0-20181017203307-c2dcc5cca94a
 * go: downloading github.com/spacemonkeygo/spacelog v0.0.0-20180420211403-2296661a0572
 * % ./pta
 * 569ea8d2d77389ca0c5329872660c721eb02a5a8e41dcf1e2fe8a9b89debc928
 *
 * ref.
 * https://golang.org/pkg/
 *
 */
package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/spacemonkeygo/openssl"
	"hash/crc32"
)

func main() {
	ks := flag.String("key", "00112233445566778899aabbccddeeff", "Key")
	is := flag.String("iv", "00112233445566778899aabbccddeeff", "IV")
	us := flag.String("url", "/example.mp4", "URL path to be accepted")
	ts := flag.Int("date", 1893423600, "Expiring Date using Unix time")
	flag.Parse()
	key, _ := hex.DecodeString(*ks)
	iv, _ := hex.DecodeString(*is)
	date := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(date, uint64(*ts))
	url := []byte(*us)
	var plain []byte
	plain = append(plain, date...)
	plain = append(plain, url...)
	crc := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(crc, crc32.ChecksumIEEE(plain))
	plain = append(crc, plain...)
	cipher, _ := openssl.GetCipherByName("aes-128-cbc")
	eCtx, _ := openssl.NewEncryptionCipherCtx(cipher, nil, key, iv)
	cipherbytes, _ := eCtx.EncryptUpdate(plain)
	var cipherstring string = string(cipherbytes)
	finalbytes, _ := eCtx.EncryptFinal()
	cipherstring += string(finalbytes)
	fmt.Print(hex.EncodeToString([]byte(cipherstring)), "\n")
}
