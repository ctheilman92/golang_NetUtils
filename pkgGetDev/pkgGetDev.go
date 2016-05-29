/*****************

attempt to run device lookup Net_Utils/netUtils.go

******************/


package getdev

import (
    "fmt"
    "log"
    "github.com/google/gopacket/pcap"
)


func FindAllDevs() {
    //find all devices
    devices, err := pcap.FindAllDevs()
    if err != nil {
        log.Fatal(err)
    }

    //print device information
    fmt.Println("Devices Found: ")
    fmt.Println("================================================")

    for _, device := range devices {
        fmt.Println("\nName: ", device.Name)
        fmt.Println("Description: ", device.Description)
        fmt.Println("Devices addresses: ", device.Description)
        for _, address := range device.Addresses {
            fmt.Println("- IP address: ", address.IP)
            //fmt.Println("- Subnet Mask: ", address.Netmask)
        }
    }
}
