package capture

import (
    "bufio"
    "fmt"
    "os"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/pcapgo"
    "log"
    "time"
    "regexp"
)

var (
    pcapFile        string
    device          string
    snapshot_len    int32 = 1024
    promiscuous     bool = false
    err             error
    timeout         time.Duration = 50 * time.Second
    handle          *pcap.Handle
    packetCount     int = 0
    breakflag       bool
)

//CAPTURE ALL PACKETS OUTPUT TO CONSOLE
func AllToConsole() {
    //attempting
    // dojobs := make(chan int)
    // quit := make(chan int)

    fmt.Printf("[*]Enter a device to capture: ")
    fmt.Scanf("%s", &device)

    //set or reset breakflag
    breakflag = false

    //open Devices
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    fmt.Println("OK")
    fmt.Println("[*]Press ENTER anytime to quit capturing\n================================================")

    //goroutine grab keyboard interrupt
    go keyinterrupt()

    //Process all packets (use var handle as source)
    packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSrc.Packets() {
        if breakflag == true { break }
        //process packetSrc
        fmt.Println(packet)
    }
}

//CAPTURE HTTP ONLY OUTPUT TO CONSOLE
func HttpToConsole() {
    //attempting
    // dojobs := make(chan int)
    // quit := make(chan int)

    fmt.Printf("[*]Enter a device to capture: ")
    fmt.Scanf("%s", &device)

    //set or reset breakflag
    breakflag = false

    //open Devices
    //snapshotLen var problem converting so use literal number
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    //goroutine grab keyboard interrupt
    go keyinterrupt()

    //set filter
    //handle.SetBPFFilter
    var filter = "tcp and port 80"
    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("[*]Only Capturing TCP PORT 80 Packets...\n")

    fmt.Printf("[*] Press ENTER anytime to quit capturing\n================================================")
    //get packets
    packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSrc.Packets() {
        if breakflag == true { break }
        //do something with packet here
        fmt.Println(packet)
    }
}

//CAPTURE ALL AND WRITE TO PCAP FILE
func AllToPcap() {
    //specify dev
    fmt.Printf("[*]Enter a device to capture: ")
    fmt.Scanf("%s", &device)
    fmt.Println()

    fmt.Printf("[*]Designate your PCAP-file [FORMAT: /path/to/filename.pcap]: ")
    fmt.Scanf("%s", &pcapFile)
    //check args for .pcap extension name
    extCheck(pcapFile)
    fmt.Println("================================================")
    //open output pcap file and write header
    f, _ := os.Create(pcapFile)
    w := pcapgo.NewWriter(f)
    w.WriteFileHeader(1024, layers.LinkTypeEthernet)
    defer f.Close()

    //open device for capturing
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {
        fmt.Printf("error opening device %s: %v", device, err)
        os.Exit(1)
    }
    defer handle.Close()

    //start processing packets
    packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSrc.Packets() {
        fmt.Println(packet)
        w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
        packetCount++

        //capture 100 then stop
        if packetCount > 100 { break }
    }
}

//CAPTURE HTTP ONLY AND WRITE TO PCAP FILE
func HttpToPcap() {
    //specify dev
    fmt.Printf("[*]Enter a device to capture: ")
    fmt.Scanf("%s", &device)
    fmt.Println()

    fmt.Printf("[*]Designate your PCAP-file [FORMAT: /path/to/filename.pcap]: ")
    fmt.Scanf("%s", &pcapFile)
    //check args for .pcap extension name
    extCheck(pcapFile)
    fmt.Println("================================================")
    //open output pcap file and write header
    f, _ := os.Create(pcapFile)
    w := pcapgo.NewWriter(f)
    w.WriteFileHeader(1024, layers.LinkTypeEthernet)
    defer f.Close()

    //open device for capturing
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {
        fmt.Printf("error opening device %s: %v", device, err)
        os.Exit(1)
    }
    defer handle.Close()

    //set filter
    //handle.SetBPFFilter
    var filter = "tcp and port 80"
    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Only Capturing TCP PORT 80 Packets...")

    //start processing packets
    packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSrc.Packets() {
        fmt.Println(packet)
        w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
        packetCount++

        //capture 100 then stop
        if packetCount > 100 { break }
    }
}


/******** /
***************************
    background functions
***************************
/ *******/


func extCheck(filename string) {
    //NOTE: 2 backslashes used to handle string parsing escape sequence error
    //real regex = (^.*\.(pcap)
    regxMatch, _ := regexp.MatchString("^.*\\.(pcap)$", filename)
    if regxMatch == false {
        fmt.Println("[***]ERROR IN NAME\nPlease use correct pcap extension!\n[***]USAGE:  ./writePcap NAME.pcap")
        os.Exit(1)
    }
    return
}


// //goroutine look for interrupt to break
func keyinterrupt() {
    fmt.Println("FOR FUCKS SAKE AL! WTF! \n\n\n")
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        keydown := scanner.Text()
        if err := scanner.Err(); err != nil {
            fmt.Println(err)
            os.Exit(1)
        }

        if keydown == "" {
            fmt.Println("\n\n\n[***] PACKET STREAM HALTED!\n")
            breakflag = true
            break
        }
    }
}
