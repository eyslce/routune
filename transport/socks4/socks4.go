package socks4

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/eyslce/routune/component/auth"

	"github.com/eyslce/protobytes"
)

// Version 是 SOCKS4 协议的版本号 (0x04)
const Version = 0x04

// Command 定义了 SOCKS4 命令的类型
type Command = uint8

const (
	CmdConnect Command = 0x01 // CONNECT 命令，用于建立 TCP 连接
	CmdBind    Command = 0x02 // BIND 命令，用于建立 FTP 式的数据连接（routune 中未使用）
)

// Code 定义了 SOCKS4 响应代码的类型
type Code = uint8

const (
	RequestGranted          Code = 90 // 请求已授予
	RequestRejected         Code = 91 // 请求被拒绝或失败
	RequestIdentdFailed     Code = 92 // 请求被拒绝，因为 SOCKS 服务器无法连接到客户端上的 identd 服务
	RequestIdentdMismatched Code = 93 // 请求被拒绝，因为客户端程序和 identd 报告了不同的用户 ID
)

var (
	errVersionMismatched   = errors.New("version code mismatched") // 错误：版本号不匹配
	errCommandNotSupported = errors.New("command not supported")   // 错误：命令不支持 (例如，非 CONNECT 命令)
	errIPv6NotSupported    = errors.New("IPv6 not supported")      // 错误：SOCKS4 不支持 IPv6 地址

	ErrRequestRejected         = errors.New("request rejected or failed")                                                       // 错误：请求被拒绝或失败 (对应代码 91)
	ErrRequestIdentdFailed     = errors.New("request rejected because SOCKS server cannot connect to identd on the client")     // 错误：无法连接 identd (对应代码 92)
	ErrRequestIdentdMismatched = errors.New("request rejected because the client program and identd report different user-ids") // 错误：identd 用户 ID 不匹配 (对应代码 93)
	ErrRequestUnknownCode      = errors.New("request failed with unknown code")                                                 // 错误：未知的响应代码
)

// ServerHandshake 代表 SOCKS4 服务端握手过程。
// rw: 用于与客户端进行读写的 io.ReadWriter。
// authenticator: 用于验证客户端提供的 UserID 的认证器。
// 返回解析出的目标地址 (addr)，客户端请求的命令 (command)，以及可能发生的错误 (err)。
func ServerHandshake(rw io.ReadWriter, authenticator auth.Authenticator) (addr string, command Command, err error) {
	// SOCKS4 请求的固定部分是 8 字节：VN(1) CD(1) DSTPORT(2) DSTIP(4)
	var req [8]byte
	// 读取这 8 个字节
	if _, err = io.ReadFull(rw, req[:]); err != nil {
		return
	}

	r := protobytes.BytesReader(req[:]) // 使用 protobytes 进行字节解析
	// 检查版本号
	if r.ReadUint8() != Version {
		err = errVersionMismatched
		return
	}

	// 读取命令，routune 只支持 CONNECT 命令
	if command = r.ReadUint8(); command != CmdConnect {
		err = errCommandNotSupported
		return
	}

	var (
		host   string // 目标主机名（如果使用 SOCKS4A）
		port   string // 目标端口号（字符串形式）
		code   Code   // SOCKS4 响应代码
		userID []byte // 客户端提供的 UserID
	)

	// 读取 UserID，UserID 是一个以 NULL 字节结尾的字符串
	if userID, err = readUntilNull(rw); err != nil {
		return
	}

	dstPort := r.ReadUint16be() // 读取目标端口号 (DSTPORT)，网络字节序（大端）
	dstAddr := r.ReadIPv4()     // 读取目标 IP 地址 (DSTIP)

	// SOCKS4A 扩展：如果 DSTIP 的前三个字节是 0，且最后一个字节非 0 (0.0.0.x, x != 0)，
	// 则表示客户端无法解析域名，并在 UserID 后额外发送了目标域名。
	if isReservedIP(dstAddr) {
		var target []byte
		// 读取以 NULL 字节结尾的目标域名
		if target, err = readUntilNull(rw); err != nil {
			return
		}
		host = string(target)
	}

	port = strconv.Itoa(int(dstPort)) // 将端口号转换为字符串
	// 构建目标地址字符串
	if host != "" { // 如果是 SOCKS4A，使用域名
		addr = net.JoinHostPort(host, port)
	} else { // 否则使用 IP 地址
		addr = net.JoinHostPort(dstAddr.String(), port)
	}

	// SOCKS4 只支持基于 UserID 的认证 (或者说，它没有一个标准的认证流程，UserID 通常用于日志记录或简单的访问控制)
	// 如果没有提供认证器，或者认证器验证通过 (UserID 作为用户名，密码为空)
	if authenticator == nil || authenticator.Verify(string(userID), "") {
		code = RequestGranted // 请求授予
	} else {
		code = RequestIdentdMismatched // 认证失败，返回 IdentdMismatched 代码
		err = ErrRequestIdentdMismatched
	}

	// 构建 SOCKS4 响应
	// 响应格式：VN(1) CD(1) DSTPORT(2) DSTIP(4)
	// VN 必须是 0
	reply := protobytes.BytesWriter(make([]byte, 0, 8))
	reply.PutUint8(0)    // VN (Reply Version, must be 0)
	reply.PutUint8(code) // CD (Result Code)
	// DSTPORT 和 DSTIP 在响应中通常不被客户端使用，可以填请求中的值或者全 0
	reply.PutUint16be(dstPort)
	reply.PutSlice(dstAddr.AsSlice())

	// 将响应发送给客户端
	_, wErr := rw.Write(reply.Bytes())
	// 如果之前没有错误，则将写入错误赋值给 err
	if err == nil {
		err = wErr
	}
	return
}

// ClientHandshake 代表 SOCKS4 客户端握手过程。
// rw: 用于与 SOCKS4 服务器进行读写的 io.ReadWriter。
// addr: 要连接的目标地址 (host:port)。
// command: 要执行的 SOCKS4 命令 (通常是 CmdConnect)。
// userID: 要发送给服务器的 UserID 字符串。
// 返回可能发生的错误。
func ClientHandshake(rw io.ReadWriter, addr string, command Command, userID string) (err error) {
	// 解析目标地址为主机和端口
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	// 将端口字符串转换为 uint16
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return err
	}

	ip, err := netip.ParseAddr(host) // 尝试将主机名解析为 IP 地址
	if err != nil {                  // 如果解析失败，说明 host 是一个域名 (SOCKS4A)
		// 对于 SOCKS4A，将 DSTIP 设置为 0.0.0.x (x 非 0)，这里用 0.0.0.1
		ip = netip.AddrFrom4([4]byte{0, 0, 0, 1})
	} else if ip.Is6() { // 如果是 IPv6 地址
		return errIPv6NotSupported // SOCKS4 不支持 IPv6
	}

	// 构建 SOCKS4 请求
	req := protobytes.BytesWriter{}
	req.PutUint8(Version)         // VN (Version)
	req.PutUint8(command)         // CD (Command)
	req.PutUint16be(uint16(port)) // DSTPORT
	req.PutSlice(ip.AsSlice())    // DSTIP
	req.PutString(userID)         // UserID
	req.PutUint8(0)               /* NULL 字节结束 UserID */

	if isReservedIP(ip) /* SOCKS4A */ { // 如果是 SOCKS4A (即 DSTIP 是 0.0.0.x)
		req.PutString(host) // 在 UserID 后附加目标主机名
		req.PutUint8(0)     /* NULL 字节结束主机名 */
	}

	// 将请求发送给 SOCKS4 服务器
	if _, err = rw.Write(req.Bytes()); err != nil {
		return err
	}

	// 读取服务器的响应，固定 8 字节：VN(1) CD(1) DSTPORT(2) DSTIP(4)
	var resp [8]byte
	if _, err = io.ReadFull(rw, resp[:]); err != nil {
		return err
	}

	// 响应的第一个字节 (VN) 必须是 0
	if resp[0] != 0x00 {
		return errVersionMismatched
	}

	// 根据响应的第二个字节 (CD - Code) 判断结果
	switch resp[1] {
	case RequestGranted: // 请求成功
		return nil
	case RequestRejected: // 请求被拒绝
		return ErrRequestRejected
	case RequestIdentdFailed: // Identd 失败
		return ErrRequestIdentdFailed
	case RequestIdentdMismatched: // Identd 用户 ID 不匹配
		return ErrRequestIdentdMismatched
	default: // 未知代码
		return ErrRequestUnknownCode
	}
}

// isReservedIP 检查给定的 IP 地址是否是 SOCKS4A 协议中用于指示后面跟随域名的保留 IP 地址。
// 根据 SOCKS4A 规范，如果客户端无法解析目标主机的域名，
// 它应该将 DSTIP 的前三个字节设置为 NULL，最后一个字节设置为非零值 (0.0.0.x, x != 0)。
// ip: 要检查的 netip.Addr。
// 返回 true 如果 IP 地址符合 SOCKS4A 的保留格式，否则返回 false。
func isReservedIP(ip netip.Addr) bool {
	// 定义子网 0.0.0.0/24 (即 0.0.0.0 到 0.0.0.255)
	subnet := netip.PrefixFrom(
		netip.AddrFrom4([4]byte{0, 0, 0, 0}),
		24, // 前 24 位匹配，即前三个字节
	)

	// IP 不能是未指定地址 (0.0.0.0)，并且必须在 0.0.0.0/24 子网内
	// 这确保了 IP 是 0.0.0.x 的形式，其中 x 可以是 1-255
	return !ip.IsUnspecified() && subnet.Contains(ip)
}

// readUntilNull 从 io.Reader 中读取字节，直到遇到 NULL 字节 (0x00) 或发生错误。
// r: 输入的 io.Reader。
// 返回读取到的字节切片 (不包括 NULL 字节) 和可能发生的错误。
func readUntilNull(r io.Reader) ([]byte, error) {
	buf := protobytes.BytesWriter{} // 用于存储读取的字节
	var data [1]byte                // 每次读取一个字节的缓冲区

	for {
		// 从 Reader 中读取一个字节
		if _, err := r.Read(data[:]); err != nil {
			return nil, err // 发生错误则返回
		}
		// 如果读取到的是 NULL 字节
		if data[0] == 0 {
			return buf.Bytes(), nil // 返回已读取的字节内容
		}
		// 将非 NULL 字节追加到缓冲区
		buf.PutUint8(data[0])
	}
}
