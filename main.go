package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"log"
	"os"
)

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "\nsyntax: %s <file with list of contributions>\n", os.Args[0])
	fmt.Fprintf(out, "\noptions:\n")
	flag.PrintDefaults()
}

func errorExit(description string) {
	out := flag.CommandLine.Output()

	fmt.Fprintln(out, description)
	flag.Usage()
	fmt.Fprintf(out, "\n")
	os.Exit(2)
}

func assertNoError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	localityFlag := flag.Uint("locality", 0, "TPM init locality")
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() != 1 {
		errorExit("exactly one argument is expected")
	}

	listFilePath := flag.Arg(0)

	contribList, err := parseListFile(listFilePath)
	assertNoError(err)

	if len(contribList) == 0 {
		errorExit("the provided file was empty")
	}
	hashAlgo := hashAlgoFromDigestSize(len(contribList[0]))
	if hashAlgo == nil {
		errorExit(fmt.Sprintf("unexpected digest length %d (does not match neither SHA1 nor SHA256)", len(contribList[0])))
	}

	resultDigest := replay(hashAlgo, uint8(*localityFlag), contribList)
	fmt.Printf("result digest is: %X\n", resultDigest)
}

func replay(
	hasher hash.Hash,
	locality uint8,
	contribs []Digest,
) Digest {

	v := make([]byte, hasher.Size())
	v[hasher.Size()-1] = 3

	extend := func(hasher hash.Hash, e []byte) {
		hasher.Write(v)
		hasher.Write(e)
		v = hasher.Sum(nil)
		hasher.Reset()
		fmt.Printf("<- %X: %X\n", e, v)
	}
	for _, contrib := range contribs {
		extend(hasher, contrib)
	}

	return Digest(v)
}

type Digest []byte

func parseListFile(listFilePath string) ([]Digest, error) {
	listFile, err := os.Open(listFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open file '%s': %w", listFilePath, err)
	}
	defer listFile.Close()

	var result []Digest
	scanner := bufio.NewScanner(listFile)
	for scanner.Scan() {
		str := scanner.Text()
		b, err := hex.DecodeString(str)
		if err != nil {
			return nil, fmt.Errorf("unable to un-HEX value '%s': %w", str, err)
		}
		if len(result) != 0 && len(b) != len(result[0]) {
			// the length should be the same for all contributions
			return nil, fmt.Errorf("inconsistent length: entries %X and %X has different lengths: %d and %d", result[0], b, len(result[0]), len(b))
		}
		result = append(result, Digest(b))
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unable to scan a line from the file '%s': %w", listFilePath, err)
	}

	return result, nil
}

func hashAlgoFromDigestSize(digestSize int) hash.Hash {
	switch digestSize {
	case sha1.Size:
		return sha1.New()
	case sha256.Size:
		return sha256.New()
	}
	return nil
}
