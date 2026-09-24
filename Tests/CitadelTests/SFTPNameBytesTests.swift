import NIO
import XCTest
@testable import Citadel

/// `SSH_FXP_NAME` components carry the filename's bytes beside the decoded string: a server may send a
/// name that is not valid UTF-8, and `String(decoding:)` replaces the bad bytes with U+FFFD. Parsed
/// through the real parser on `EmbeddedChannel` — no server required.
final class SFTPNameBytesTests: XCTestCase {
    private func parse(_ wire: ByteBuffer) throws -> SFTPMessage {
        let inbound = EmbeddedChannel(handler: ByteToMessageHandler(SFTPMessageParser()))
        try inbound.writeInbound(wire)
        return try XCTUnwrap(try inbound.readInbound(as: SFTPMessage.self))
    }

    /// uint32 length · byte 104 (SSH_FXP_NAME) · uint32 request-id · uint32 count · (string filename ·
    /// string longname · attrs) — one component, no attribute flags.
    private func nameMessage(requestId: UInt32, filenameBytes: [UInt8], longname: String) -> ByteBuffer {
        var body = ByteBufferAllocator().buffer(capacity: 64)
        body.writeInteger(SFTPMessageType.name.rawValue)
        body.writeInteger(requestId)
        body.writeInteger(UInt32(1))
        body.writeInteger(UInt32(filenameBytes.count))
        body.writeBytes(filenameBytes)
        body.writeInteger(UInt32(longname.utf8.count))
        body.writeString(longname)
        body.writeInteger(UInt32(0))   // attribute flags: nothing follows
        var wire = ByteBufferAllocator().buffer(capacity: body.readableBytes + 4)
        wire.writeInteger(UInt32(body.readableBytes))
        wire.writeBuffer(&body)
        return wire
    }

    func testAnUndecodableFilenameArrivesAsALossyStringWithItsBytesBeside() throws {
        let bytes: [UInt8] = [0x73, 0x63, 0xFF, 0x6E, 0x2E, 0x74, 0x69, 0x66]   // "sc\xffn.tif"
        let parsed = try parse(nameMessage(requestId: 5, filenameBytes: bytes, longname: "-rw-r--r-- sc?n.tif"))
        guard case .name(let name) = parsed else {
            return XCTFail("parsed as \(parsed.debugDescription), expected .name")
        }
        XCTAssertEqual(name.requestId, 5)
        XCTAssertEqual(name.components.count, 1)
        let component = try XCTUnwrap(name.components.first)
        XCTAssertEqual(component.filename, "sc\u{FFFD}n.tif", "the string is lossy — the byte 0xFF became U+FFFD")
        XCTAssertEqual(component.filenameBytes, bytes, "the bytes are the server's, unchanged")
        XCTAssertNotEqual(Array(component.filename.utf8), bytes)
    }

    func testAValidFilenamesBytesAreItsUTF8() throws {
        let bytes = Array("Caf\u{00E9}.txt".utf8)
        let parsed = try parse(nameMessage(requestId: 6, filenameBytes: bytes, longname: "-rw-r--r-- Caf\u{00E9}.txt"))
        guard case .name(let name) = parsed, let component = name.components.first else {
            return XCTFail("parsed as \(parsed.debugDescription), expected .name")
        }
        XCTAssertEqual(component.filename, "Caf\u{00E9}.txt")
        XCTAssertEqual(component.filenameBytes, bytes)
        XCTAssertEqual(Array(component.filename.utf8), component.filenameBytes)
    }

    func testTheSerializerWritesTheBytesBack() throws {
        let bytes: [UInt8] = [0x73, 0x63, 0xFF, 0x6E]
        let component = SFTPPathComponent(filename: String(decoding: bytes, as: UTF8.self), filenameBytes: bytes, longname: "x", attributes: .none)
        let outbound = EmbeddedChannel(handler: MessageToByteHandler(SFTPMessageSerializer()))
        try outbound.writeOutbound(SFTPMessage.name(.init(requestId: 8, components: [component])))
        let wire = try XCTUnwrap(try outbound.readOutbound(as: ByteBuffer.self))
        let parsed = try parse(wire)
        guard case .name(let name) = parsed, let received = name.components.first else {
            return XCTFail("parsed as \(parsed.debugDescription), expected .name")
        }
        XCTAssertEqual(received.filenameBytes, bytes, "a round trip never mangles a name")
        XCTAssertEqual(received.filename, "sc\u{FFFD}n")
    }

    func testTheStringOnlyInitializerCarriesItsUTF8() {
        let component = SFTPPathComponent(filename: "plain.txt", longname: "x", attributes: .none)
        XCTAssertEqual(component.filenameBytes, Array("plain.txt".utf8))
    }
}
