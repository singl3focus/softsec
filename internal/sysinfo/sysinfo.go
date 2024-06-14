package sysinfo

import (
	"log"
	"bytes"

	"github.com/denisbrodbeck/machineid"
	"github.com/elastic/go-sysinfo"
)

const (
	sysInfoSep = "&&"
)

func GetFullMachineInfo() ([]byte, error) {
	id, err := GetMachineId()
	if err != nil {
		return nil, err
	}

	hostInfo, err := GetHostInfo()
	if err != nil {
		return nil, err
	}

	res := append(hostInfo, []byte(sysInfoSep)...)
	return append(res, id...), nil
}

func GetMachineId() ([]byte, error) {
	machineID, err := machineid.ID()
	if err != nil {
		return nil, err
	}

	return []byte(machineID), nil
}
	
func GetHostInfo() ([]byte, error) {
	host, err := sysinfo.Host()
	if err != nil {
		return nil, err
	}
	
	hostInfo := host.Info()
	machineInfo := hostInfo.OS.Name + sysInfoSep + hostInfo.UniqueID + sysInfoSep + hostInfo.Architecture
	
	return []byte(machineInfo), nil
}

// DisplayData - display data in a structure
func DisplayData(data []byte) {
	infoSlice := bytes.Split(data, []byte(sysInfoSep))

	log.Println("CLIENT MACHINE INFO: ")
	for _, v := range infoSlice {
		log.Println(string(v))
	}
	log.Println("______________________")
}