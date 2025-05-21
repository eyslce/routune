// Package tunnel 提供了网络隧道的核心功能实现
package tunnel

import (
	"errors"
	"net"
	"net/netip"
	"time"

	N "github.com/eyslce/clash/common/net"
	"github.com/eyslce/clash/common/pool"
	C "github.com/eyslce/clash/constant"
)

// handleUDPToRemote 处理UDP数据包发送到远程服务器的逻辑
// packet: UDP数据包
// pc: 数据包连接
// metadata: 连接元数据
// 返回值: 如果发送失败返回错误，成功返回nil
func handleUDPToRemote(packet C.UDPPacket, pc C.PacketConn, metadata *C.Metadata) error {
	// 获取UDP地址
	addr := metadata.UDPAddr()
	if addr == nil {
		return errors.New("udp addr invalid")
	}

	// 将数据包写入远程连接
	if _, err := pc.WriteTo(packet.Data(), addr); err != nil {
		return err
	}
	// 重置读取超时时间
	pc.SetReadDeadline(time.Now().Add(udpTimeout))

	return nil
}

// handleUDPToLocal 处理从远程服务器接收UDP数据包并转发到本地的逻辑
// packet: UDP数据包
// pc: 数据包连接
// key: NAT表键值
// oAddr: 原始地址
// fAddr: 转发地址
func handleUDPToLocal(packet C.UDPPacket, pc net.PacketConn, key string, oAddr, fAddr netip.Addr) {
	// 获取UDP缓冲区
	buf := pool.Get(pool.UDPBufferSize)
	defer pool.Put(buf)
	defer natTable.Delete(key)
	defer pc.Close()

	for {
		// 设置读取超时
		pc.SetReadDeadline(time.Now().Add(udpTimeout))
		// 从连接读取数据
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}

		// 处理UDP地址映射
		fromUDPAddr := *from.(*net.UDPAddr)
		if fAddr.IsValid() {
			fromAddr, _ := netip.AddrFromSlice(fromUDPAddr.IP)
			fromAddr = fromAddr.Unmap()
			if oAddr == fromAddr {
				fromUDPAddr.IP = fAddr.AsSlice()
			}
		}

		// 将数据写回原始数据包
		_, err = packet.WriteBack(buf[:n], &fromUDPAddr)
		if err != nil {
			return
		}
	}
}

// handleSocket 处理TCP连接的转发
// ctx: 连接上下文
// outbound: 出站连接
func handleSocket(ctx C.ConnContext, outbound net.Conn) {
	N.Relay(ctx.Conn(), outbound)
}
