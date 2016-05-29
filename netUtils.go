package main

import (
    "fmt"
    "os"
    "os/exec"
    "github.com/ctheilman92/Net_Utils/pkgGetDev"
    "github.com/ctheilman92/Net_Utils/pkgCaptureDev"
    "github.com/ctheilman92/Net_Utils/pkgRead"
    "log"
)


/************************************************
*************************************************
*** Author: Cameron Heilman
*** package network PCAP & device handler
*************************************************
************************************************/

var (
    running     bool = true
    ans         int
    exiter      string
)



func main() {
    for running {

        fmt.Printf("[*************************************************]\n")
        fmt.Println(" W3lc0me: S3l3ct a N3tw0rking Utility from b3l0w")
        fmt.Printf("[*************************************************]\n")

        //user input selection
        Menu()
        fmt.Printf("Choice: ")
        fmt.Scanf("%d", &ans)

        switch ans {
        case 1:
            c := exec.Command("clear")
            c.Stdout = os.Stdout
            c.Run()
            fmt.Println("LIST ALL DEVICES")
            getdev.FindAllDevs()
            break
        case 2:
            c := exec.Command("clear")
            c.Stdout = os.Stdout
            c.Run()
            fmt.Println("LIVE CONSOLE CAPTURE")
            capture.AllToConsole()
            break
        case 3:
            c := exec.Command("clear")
            c.Stdout = os.Stdout
            c.Run()
            fmt.Println("[*]HTTP CONSOLE CAPTURE")
            capture.HttpToConsole()
            break
        case 4:
            c := exec.Command("clear")
            c.Stdout = os.Stdout
            c.Run()
            fmt.Println("CREATING PCAP FILE")
            capture.AllToPcap()
            break
        case 5:
            c := exec.Command("clear")
            c.Stdout = os.Stdout
            c.Run()
            fmt.Println("CREATING HTTP-PCAP FILE")
            capture.HttpToPcap()
            break
        case 6:
            c := exec.Command("clear")
            c.Stdout = os.Stdout
            c.Run()
            fmt.Println("READING PCAP FILE")
            readpcap.Reader()
            break
        default:
            fmt.Println("nothing selected. QUITTING!!!")
            os.Exit(0)
        }

    fmt.Printf("[***]\nBACK TO MAIN MENU?(y/N): ")
    fmt.Scanf("%s", &exiter)
    if exiter == "y" { exiter = "Y" }    //lul
    if exiter != "Y" && exiter != "n" {
        log.Printf("\nExiting...")
        break
        running = false
    } else if exiter == "n" {
        fmt.Println("Quitting...")
        running = false
    } else {
        c := exec.Command("clear")
        c.Stdout = os.Stdout
        c.Run()
    }
    }
}


func Menu() {
    fmt.Println("[*1*]  Device Information (All)")
    fmt.Println("[*2*]  Live Packet Capture [OUT:CONSOLE]")
    fmt.Println("[*3*]  HTTP Live Packet Capture [OUT:CONSOLE]")
    fmt.Println("[*4*]  Create PCAP File [100 PACKETS]")
    fmt.Println("[*5*]  Create HTTP-filtered PCAP File [100 PACKETS]")
    fmt.Println("[*6*]  Read Existing PCAP file")
    return
}
