package readpcap

import (
    //"os"
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "log"
)

var (
    pcapFile    string
    handle      *pcap.Handle
    err         error
)

func Reader() {

    fmt.Printf("[*]Specify PCAP file to read: ")
    fmt.Scanf("%s", &pcapFile)

    //open output pcap file and write header
    handle, err = pcap.OpenOffline(pcapFile)
    if err != nil { log.Fatal(err) }
    defer handle.Close()


    //loop through packets in file
    fmt.Println("[*] Reading From File: ")
    fmt.Println("================================================")
    packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSrc.Packets() {
        fmt.Println(packet)
    }
}
