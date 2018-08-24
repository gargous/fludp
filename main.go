package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
)

func move(in []byte, offset int) (out []byte, rest []byte) {
	out = in[:offset]
	rest = in[offset:]
	return
}

func ipline(inlen int, in []byte) (n int, out uint32, rest []byte) {
	l1, rest := move(in, 4)
	out = binary.BigEndian.Uint32(l1)
	n = inlen - 4
	return
}

func movebit(in uint32, offset uint) (out uint32, rest uint32) {
	out = in >> (32 - offset)
	rest = in << offset
	return
}

func inverse(in uint16) (out uint16) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint16(buf, in)
	out = binary.LittleEndian.Uint16(buf)
	return
}

type IPPack struct {
	version  uint32
	ihl      uint32
	ds       uint32
	ecn      uint32
	tl       uint32
	id       uint32
	flags    uint32
	offset   uint32
	ttl      uint32
	protocol uint32
	chuckSum uint32
	srcIP    net.IP
	dscIP    net.IP
	content  []byte
}

func (i IPPack) String() (out string) {
	iv := reflect.ValueOf(i)
	it := reflect.TypeOf(i)
	outl := make([]string, 0)
	for i := 0; i < it.NumField(); i++ {
		f := it.Field(i)
		outl = append(outl, fmt.Sprintf("%s:%v", f.Name, iv.FieldByName(f.Name)))
	}
	out = fmt.Sprintf("{%s}", strings.Join(outl, ","))
	return
}

func server(host string, c chan error) {
	go func() {
		laddr, err := net.ResolveIPAddr("ip4", host)
		if err != nil {
			c <- errors.New("Resolve Server IP: " + err.Error())
			return
		}
		conn, err := net.ListenIP("ip:4", laddr)
		if err != nil {
			c <- errors.New("Listen IP: " + err.Error())
			return
		}
		var buff [1024]byte
		for {
			b := buff[:]
			n, err := conn.Read(b)
			if err != nil {
				c <- errors.New("Read IP: " + err.Error())
				return
			}
			if n < 20 {
				c <- errors.New("Read IP: No IP Info")
				return
			}
			ipack := IPPack{}
			next := b
			n, l1, next := ipline(n, next)
			ipack.version, l1 = movebit(l1, 4)
			ipack.ihl, l1 = movebit(l1, 4)
			ipack.ds, l1 = movebit(l1, 6)
			ipack.ecn, l1 = movebit(l1, 2)
			ipack.tl, _ = movebit(l1, 16)
			ipack.tl = uint32(inverse(uint16(ipack.tl)))

			n, l2, next := ipline(n, next)
			ipack.id, l2 = movebit(l2, 16)
			ipack.flags, l2 = movebit(l2, 2)
			ipack.offset, l2 = movebit(l2, 14)

			n, l3, next := ipline(n, next)
			ipack.ttl, l3 = movebit(l3, 8)
			ipack.protocol, l3 = movebit(l3, 8)
			ipack.chuckSum, l3 = movebit(l3, 16)
			n, ip, next := ipline(n, next)
			ipstr := make([]byte, 4)
			binary.BigEndian.PutUint32(ipstr, ip)
			ipack.srcIP = ipstr
			n, ip, next = ipline(n, next)
			ipstr = make([]byte, 4)
			binary.BigEndian.PutUint32(ipstr, ip)
			ipack.dscIP = ipstr
			ipack.content = next[:n]
			fmt.Println("Recv:", ipack, string(ipack.content))
		}
	}()
}

func client(host string, c chan error) {
	go func() {
		laddr, err := net.ResolveIPAddr("ip4", host)
		if err != nil {
			c <- errors.New("Resolve Client IP: " + err.Error())
			return
		}
		conn, err := net.DialIP("ip:4", nil, laddr)
		if err != nil {
			c <- errors.New("Dial IP: " + err.Error())
			return
		}
		var buff [1024]byte
		for {
			b := buff[:]
			n, err := os.Stdin.Read(b)
			if err != nil {
				c <- errors.New("Read Stdin: " + err.Error())
				return
			}
			_, err = conn.Write(b[:n])
			if err != nil {
				c <- errors.New("Write IP: " + err.Error())
				return
			}
		}
	}()
}

func main() {
	c := make(chan error)
	server("127.0.0.1", c)
	client("127.0.0.1", c)
	err := <-c
	fmt.Println(err)
}
